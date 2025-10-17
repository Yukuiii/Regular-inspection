"""
签到核心逻辑模块
整合 AnyRouter 和 AgentRouter 的签到功能
"""

import asyncio
import hashlib
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

import httpx
from playwright.async_api import async_playwright

from config import parse_cookies


BALANCE_HASH_FILE = 'balance_hash.txt'
BALANCE_DATA_FILE = 'balance_data.json'


class RouterCheckin:
    """Router平台签到类"""

    def __init__(self):
        self.last_balance_hash = self._load_balance_hash()
        self.last_balance_data = self._load_balance_data()
        self.current_balances = {}
        self.balance_changed = False

    async def run_all(self, anyrouter_accounts: List[Dict], agentrouter_accounts: List[Dict]) -> List[Dict]:
        """执行所有账号的签到"""
        results = []

        # 处理 AnyRouter 账号
        anyrouter_results = []
        for i, account in enumerate(anyrouter_accounts):
            result = await self.checkin_anyrouter(account, i)
            results.append(result)
            anyrouter_results.append(result)
            await asyncio.sleep(2)  # 避免请求过快

        # 显示 AnyRouter 平台汇总
        if anyrouter_results:
            self._print_platform_summary('AnyRouter', anyrouter_results)

        # 处理 AgentRouter 账号
        agentrouter_results = []
        for i, account in enumerate(agentrouter_accounts):
            result = await self.checkin_agentrouter(account, i)
            results.append(result)
            agentrouter_results.append(result)
            await asyncio.sleep(2)

        # 显示 AgentRouter 平台汇总
        if agentrouter_results:
            self._print_platform_summary('AgentRouter', agentrouter_results)

        # 检查余额变化
        self._check_balance_change()

        return results

    def _print_platform_summary(self, platform_name: str, platform_results: List[Dict]):
        """打印单个平台的汇总统计"""
        success_count = sum(1 for r in platform_results if r['success'])
        failed_count = len(platform_results) - success_count

        total_quota = 0
        total_used = 0
        has_balance = False

        for result in platform_results:
            if result.get('balance'):
                has_balance = True
                balance = result['balance']
                total_quota += balance['quota']
                total_used += balance['used']

        print()
        print('─' * 60)
        print(f'📊 {platform_name} 平台汇总')
        print('─' * 60)
        print(f'账号数量: {len(platform_results)} 个')
        print(f'成功: {success_count} 个 | 失败: {failed_count} 个')

        if has_balance:
            print(f'总余额: ${total_quota:.2f}')
            print(f'总已用: ${total_used:.2f}')

        print('─' * 60)

    async def checkin_anyrouter(self, account: Dict, index: int) -> Dict:
        """AnyRouter 签到"""
        platform = 'AnyRouter'
        account_name = account.get('name', f'AnyRouter账号{index+1}')

        print(f'\n[PROCESSING] 正在处理 [{platform}] {account_name}')

        try:
            # 解析配置
            cookies_data = account.get('cookies', {})
            api_user = account.get('api_user', '')

            if not api_user:
                return self._make_result(platform, account_name, False, 'API User ID 未配置')

            user_cookies = parse_cookies(cookies_data)
            if not user_cookies:
                return self._make_result(platform, account_name, False, 'Cookies 格式错误')

            # 获取 WAF cookies
            print(f'[STEP 1] 获取 WAF cookies...')
            waf_cookies = await self._get_waf_cookies(account_name, 'https://anyrouter.top/login')

            if not waf_cookies:
                return self._make_result(platform, account_name, False, '无法获取 WAF cookies')

            # 合并 cookies
            all_cookies = {**waf_cookies, **user_cookies}

            # 构建请求
            print(f'[STEP 2] 执行签到请求...')
            success, message, balance = await self._do_anyrouter_checkin(
                account_name, all_cookies, api_user
            )

            # 记录余额
            if balance:
                account_key = f'anyrouter_{account_name}'  # 使用账号名作为key
                self.current_balances[account_key] = balance

                # 显示余额变化
                self._show_balance_change(account_key, balance)

            return self._make_result(platform, account_name, success, message, balance)

        except Exception as e:
            error_msg = f'签到异常: {str(e)[:50]}'
            print(f'[ERROR] {error_msg}')
            return self._make_result(platform, account_name, False, error_msg)

    async def checkin_agentrouter(self, account: Dict, index: int) -> Dict:
        """AgentRouter 签到/保活"""
        platform = 'AgentRouter'
        account_name = account.get('name', f'AgentRouter账号{index+1}')

        print(f'\n[PROCESSING] 正在处理 [{platform}] {account_name}')

        try:
            # 检查是否使用账号密码登录
            email = account.get('email', '')
            password = account.get('password', '')

            if email and password:
                # 使用账号密码登录
                print(f'[STEP 1] 使用账号密码登录...')
                login_result = await self._login_agentrouter(email, password)

                if not login_result:
                    return self._make_result(platform, account_name, False, '账号密码登录失败')

                user_cookies = login_result['cookies']
                api_user = login_result['api_user']

                print(f'[SUCCESS] 登录成功，获取到 session')
            else:
                # 使用传统的 cookies 方式
                cookies_data = account.get('cookies', {})
                api_user = account.get('api_user', '')

                if not api_user:
                    return self._make_result(platform, account_name, False, 'API User ID 未配置')

                user_cookies = parse_cookies(cookies_data)
                if not user_cookies:
                    return self._make_result(platform, account_name, False, 'Cookies 格式错误')

                # 尝试获取 WAF cookies（尝试多个 URL）
                print(f'[STEP 1] 获取 WAF cookies...')
                waf_cookies = await self._get_waf_cookies_with_fallback(
                    account_name,
                    ['https://agentrouter.org', 'https://agentrouter.org/console']
                )

                # 合并 cookies（即使没有 WAF cookies 也继续）
                if waf_cookies:
                    user_cookies = {**waf_cookies, **user_cookies}

            all_cookies = user_cookies

            # 执行签到请求
            print(f'[STEP 2] 执行签到请求...')
            success, message, balance = await self._do_agentrouter_checkin(
                account_name, all_cookies, api_user
            )

            # 记录余额
            if balance:
                account_key = f'agentrouter_{account_name}'  # 使用账号名作为key
                self.current_balances[account_key] = balance

                # 显示余额变化
                self._show_balance_change(account_key, balance)

            return self._make_result(platform, account_name, success, message, balance)

        except Exception as e:
            error_msg = f'签到异常: {str(e)[:50]}'
            print(f'[ERROR] {error_msg}')
            return self._make_result(platform, account_name, False, error_msg)

    async def _get_waf_cookies_with_fallback(self, account_name: str, urls: List[str]) -> Optional[Dict[str, str]]:
        """尝试多个 URL 获取 WAF cookies"""
        for url in urls:
            print(f'[INFO] 尝试 URL: {url}')
            cookies = await self._get_waf_cookies(account_name, url, timeout=20000)
            if cookies:
                return cookies

        print(f'[WARN] 所有 URL 均未获取到 WAF cookies，将只使用用户 cookies')
        return None

    async def _get_waf_cookies(self, account_name: str, url: str, timeout: int = 30000) -> Optional[Dict[str, str]]:
        """使用 Playwright 获取 WAF cookies"""
        async with async_playwright() as p:
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                context = await p.chromium.launch_persistent_context(
                    user_data_dir=temp_dir,
                    headless=True,
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
                    viewport={'width': 1920, 'height': 1080},
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--disable-dev-shm-usage',
                        '--disable-web-security',
                        '--no-sandbox',
                    ],
                )

                page = await context.new_page()

                try:
                    print(f'[INFO] 访问页面获取 cookies...')
                    await page.goto(url, wait_until='domcontentloaded', timeout=timeout)

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=3000)
                    except Exception:
                        await page.wait_for_timeout(2000)

                    cookies = await page.context.cookies()

                    waf_cookies = {}
                    for cookie in cookies:
                        cookie_name = cookie.get('name')
                        cookie_value = cookie.get('value')
                        if cookie_name in ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'] and cookie_value:
                            waf_cookies[cookie_name] = cookie_value

                    print(f'[SUCCESS] 获取到 {len(waf_cookies)} 个 WAF cookies')

                    await context.close()
                    return waf_cookies if waf_cookies else None

                except Exception as e:
                    print(f'[ERROR] 获取 WAF cookies 失败: {e}')
                    await context.close()
                    return None

    async def _login_agentrouter(self, email: str, password: str) -> Optional[Dict]:
        """使用账号密码登录 AgentRouter 获取 session"""
        async with async_playwright() as p:
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                try:
                    context = await p.chromium.launch_persistent_context(
                        user_data_dir=temp_dir,
                        headless=True,
                        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
                        viewport={'width': 1920, 'height': 1080},
                        args=[
                            '--disable-blink-features=AutomationControlled',
                            '--disable-dev-shm-usage',
                            '--disable-web-security',
                            '--no-sandbox',
                        ],
                    )

                    page = await context.new_page()

                    # 尝试多个 URL 访问登录页面
                    login_urls = [
                        'https://agentrouter.org/login',
                        'https://agentrouter.org/#/login',
                        'https://agentrouter.org'
                    ]

                    login_success = False
                    for url in login_urls:
                        try:
                            print(f'[INFO] 尝试访问: {url}')
                            await page.goto(url, wait_until='domcontentloaded', timeout=20000)
                            await page.wait_for_timeout(2000)

                            # 检查是否有登录表单
                            email_input = await page.query_selector('input[type="email"], input[name="email"], input[placeholder*="邮箱"], input[placeholder*="Email"], input[placeholder*="email"]')
                            if email_input:
                                login_success = True
                                print(f'[SUCCESS] 成功访问登录页面')
                                break
                        except Exception as e:
                            print(f'[WARN] {url} 访问失败: {str(e)[:50]}')
                            continue

                    if not login_success:
                        print(f'[ERROR] 所有登录页面 URL 均访问失败')
                        await context.close()
                        return None

                    # 填写登录表单
                    try:
                        print(f'[INFO] 填写登录信息...')

                        # 查找邮箱输入框
                        email_selectors = [
                            'input[type="email"]',
                            'input[name="email"]',
                            'input[placeholder*="邮箱"]',
                            'input[placeholder*="Email"]',
                            'input[placeholder*="email"]'
                        ]

                        email_filled = False
                        for selector in email_selectors:
                            try:
                                await page.fill(selector, email, timeout=3000)
                                email_filled = True
                                print(f'[DEBUG] 邮箱输入框定位成功: {selector}')
                                break
                            except:
                                continue

                        if not email_filled:
                            print(f'[ERROR] 无法找到邮箱输入框')
                            await context.close()
                            return None

                        # 查找密码输入框
                        password_selectors = [
                            'input[type="password"]',
                            'input[name="password"]'
                        ]

                        password_filled = False
                        for selector in password_selectors:
                            try:
                                await page.fill(selector, password, timeout=3000)
                                password_filled = True
                                print(f'[DEBUG] 密码输入框定位成功: {selector}')
                                break
                            except:
                                continue

                        if not password_filled:
                            print(f'[ERROR] 无法找到密码输入框')
                            await context.close()
                            return None

                        await page.wait_for_timeout(1000)

                    except Exception as e:
                        print(f'[ERROR] 填写表单失败: {e}')
                        await context.close()
                        return None

                    # 点击登录按钮
                    try:
                        print(f'[INFO] 提交登录...')

                        login_button_selectors = [
                            'button[type="submit"]',
                            'button:has-text("登录")',
                            'button:has-text("Login")',
                            'button:has-text("Sign in")',
                            'button.login-button',
                            'input[type="submit"]'
                        ]

                        button_clicked = False
                        for selector in login_button_selectors:
                            try:
                                await page.click(selector, timeout=3000)
                                button_clicked = True
                                print(f'[DEBUG] 登录按钮点击成功: {selector}')
                                break
                            except:
                                continue

                        if not button_clicked:
                            print(f'[ERROR] 无法找到登录按钮')
                            await context.close()
                            return None

                    except Exception as e:
                        print(f'[ERROR] 点击登录按钮失败: {e}')
                        await context.close()
                        return None

                    # 等待登录完成（等待跳转或特定元素出现）
                    try:
                        print(f'[INFO] 等待登录完成...')
                        await page.wait_for_url('**/console**', timeout=15000)
                        print(f'[SUCCESS] 登录成功，已跳转到控制台')
                    except Exception:
                        # 如果没有跳转，等待一下再检查
                        await page.wait_for_timeout(5000)
                        current_url = page.url

                        # 检查是否仍在登录页面
                        if '/login' in current_url or '#/login' in current_url:
                            # 检查是否有错误提示
                            try:
                                error_msg = await page.text_content('.error-message, .alert-danger, [class*="error"]', timeout=2000)
                                print(f'[ERROR] 登录失败: {error_msg}')
                            except:
                                print(f'[ERROR] 登录失败，仍在登录页面: {current_url}')
                            await context.close()
                            return None
                        else:
                            print(f'[INFO] 当前页面: {current_url}，继续获取 cookies...')

                    # 获取所有 cookies
                    cookies = await page.context.cookies()

                    # 提取关键 cookies
                    session_cookie = None
                    waf_cookies = {}
                    api_user = None

                    for cookie in cookies:
                        cookie_name = cookie.get('name')
                        cookie_value = cookie.get('value')

                        if cookie_name == 'session':
                            session_cookie = cookie_value
                        elif cookie_name in ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2']:
                            waf_cookies[cookie_name] = cookie_value

                    if not session_cookie:
                        print(f'[ERROR] 未获取到 session cookie')
                        await context.close()
                        return None

                    # 尝试从页面获取 user ID
                    try:
                        # 访问 API 获取用户信息
                        user_info_response = await page.evaluate('''
                            async () => {
                                const response = await fetch('/api/user/self');
                                return await response.json();
                            }
                        ''')

                        if user_info_response and user_info_response.get('success'):
                            api_user = str(user_info_response.get('data', {}).get('id', ''))
                            print(f'[SUCCESS] 获取到 User ID: {api_user}')
                    except Exception as e:
                        print(f'[WARN] 无法获取 User ID: {e}')

                    await context.close()

                    # 构建返回结果
                    all_cookies = {'session': session_cookie, **waf_cookies}

                    return {
                        'cookies': all_cookies,
                        'api_user': api_user or ''
                    }

                except Exception as e:
                    print(f'[ERROR] 登录过程出错: {e}')
                    return None

    async def _do_anyrouter_checkin(self, account_name: str, cookies: Dict, api_user: str) -> tuple:
        """执行 AnyRouter 签到请求"""
        client = httpx.AsyncClient(http2=True, timeout=30.0)

        try:
            client.cookies.update(cookies)

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Referer': 'https://anyrouter.top/console',
                'Origin': 'https://anyrouter.top',
                'new-api-user': api_user,
            }

            # 获取用户信息
            balance = None
            try:
                print(f'[INFO] 尝试获取用户信息...')
                user_response = await client.get('https://anyrouter.top/api/user/self', headers=headers)
                print(f'[DEBUG] 用户信息响应: HTTP {user_response.status_code}')

                if user_response.status_code == 200:
                    user_data = user_response.json()
                    if user_data.get('success'):
                        data = user_data.get('data', {})
                        quota = round(data.get('quota', 0) / 500000, 2)
                        used = round(data.get('used_quota', 0) / 500000, 2)
                        balance = {'quota': quota, 'used': used}
                        print(f'[INFO] 当前余额: ${quota}, 已用: ${used}')
                    else:
                        print(f'[WARN] API返回失败: {user_data.get("message", "未知错误")}')
                elif user_response.status_code == 401:
                    print(f'[ERROR] ⚠️  认证失败 - Session Cookie 已过期！')
                    print(f'[ERROR] 请重新登录 https://anyrouter.top/register?aff=hgT6 获取新的 session cookie')
                    print(f'[ERROR] 并更新 GitHub Secrets 中的 ANYROUTER_ACCOUNTS 配置')
                    try:
                        error_data = user_response.json()
                        print(f'[ERROR] 错误信息: {error_data.get("message", "未知错误")}')
                    except:
                        pass
                else:
                    print(f'[WARN] 获取用户信息失败: HTTP {user_response.status_code}')
            except Exception as e:
                print(f'[ERROR] 获取余额异常: {e}')

            # 执行签到
            checkin_headers = headers.copy()
            checkin_headers.update({
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            })

            response = await client.post(
                'https://anyrouter.top/api/user/sign_in',
                headers=checkin_headers
            )

            print(f'[RESPONSE] HTTP {response.status_code}')

            if response.status_code == 200:
                try:
                    result = response.json()
                    if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
                        return True, '签到成功', balance
                    else:
                        msg = result.get('msg', result.get('message', '未知错误'))
                        return False, f'签到失败: {msg}', balance
                except Exception:
                    if 'success' in response.text.lower():
                        return True, '签到成功', balance
                    return False, '签到失败: 响应格式错误', balance
            else:
                return False, f'签到失败: HTTP {response.status_code}', balance

        except Exception as e:
            return False, f'请求异常: {str(e)[:50]}', None
        finally:
            await client.aclose()

    async def _do_agentrouter_checkin(self, account_name: str, cookies: Dict, api_user: str) -> tuple:
        """执行 AgentRouter 签到请求"""
        # AgentRouter 可能使用类似的API，这里需要根据实际情况调整
        client = httpx.AsyncClient(http2=True, timeout=30.0)

        try:
            client.cookies.update(cookies)

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Referer': 'https://agentrouter.org/console',
                'Origin': 'https://agentrouter.org',
                'new-api-user': api_user,
            }

            # 尝试获取用户信息（测试登录状态）
            balance = None
            try:
                print(f'[INFO] 尝试获取用户信息...')
                user_response = await client.get('https://agentrouter.org/api/user/self', headers=headers)
                print(f'[DEBUG] 用户信息响应: HTTP {user_response.status_code}')

                if user_response.status_code == 200:
                    user_data = user_response.json()
                    # 不显示完整响应数据，避免泄露敏感信息

                    if user_data.get('success'):
                        data = user_data.get('data', {})
                        quota = round(data.get('quota', 0) / 500000, 2)
                        used = round(data.get('used_quota', 0) / 500000, 2)
                        balance = {'quota': quota, 'used': used}
                        print(f'[INFO] 当前余额: ${quota}, 已用: ${used}')
                    else:
                        print(f'[WARN] API返回失败: {user_data.get("message", "未知错误")}')
                elif user_response.status_code == 401:
                    print(f'[ERROR] ⚠️  认证失败 - Session Cookie 已过期！')
                    print(f'[ERROR] 请重新登录 https://agentrouter.org/register?aff=7Stf 获取新的 session cookie')
                    print(f'[ERROR] 并更新 GitHub Secrets 中的 AGENTROUTER_ACCOUNTS 配置')
                    try:
                        error_data = user_response.json()
                        print(f'[ERROR] 错误信息: {error_data.get("message", "未知错误")}')
                    except:
                        pass
                else:
                    print(f'[WARN] 获取用户信息失败: HTTP {user_response.status_code}')
                    try:
                        print(f'[DEBUG] 错误响应: {user_response.text[:200]}')
                    except:
                        pass
            except Exception as e:
                print(f'[ERROR] 获取余额异常: {e}')

            # 尝试签到（如果有签到接口）
            checkin_headers = headers.copy()
            checkin_headers.update({
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            })

            try:
                response = await client.post(
                    'https://agentrouter.org/api/user/sign_in',
                    headers=checkin_headers
                )

                print(f'[RESPONSE] HTTP {response.status_code}')

                if response.status_code == 200:
                    result = response.json()
                    if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
                        return True, '签到成功', balance
                    else:
                        msg = result.get('msg', result.get('message', '未知错误'))
                        return False, f'签到失败: {msg}', balance
                elif response.status_code == 404:
                    # 如果没有签到接口，只要能获取用户信息就算成功（保活）
                    if balance:
                        return True, '保活成功（无签到接口）', balance
                    return False, '保活失败: 无法获取用户信息', None
                else:
                    return False, f'签到失败: HTTP {response.status_code}', balance

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404 and balance:
                    # 如果签到接口不存在但能获取余额，算作保活成功
                    return True, '保活成功（无签到接口）', balance
                return False, f'请求失败: {e}', balance

        except Exception as e:
            return False, f'请求异常: {str(e)[:50]}', None
        finally:
            await client.aclose()

    def _make_result(self, platform: str, name: str, success: bool,
                     message: str, balance: Optional[Dict] = None) -> Dict:
        """构建结果对象"""
        result = {
            'platform': platform,
            'name': name,
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        if balance:
            result['balance'] = balance
        return result

    def _load_balance_hash(self) -> Optional[str]:
        """加载余额哈希"""
        try:
            if os.path.exists(BALANCE_HASH_FILE):
                with open(BALANCE_HASH_FILE, 'r') as f:
                    return f.read().strip()
        except Exception:
            pass
        return None

    def _load_balance_data(self) -> Dict:
        """加载上次的余额数据"""
        try:
            if os.path.exists(BALANCE_DATA_FILE):
                with open(BALANCE_DATA_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_balance_data(self):
        """保存当前余额数据"""
        try:
            with open(BALANCE_DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.current_balances, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f'[WARN] 保存余额数据失败: {e}')

    def _show_balance_change(self, account_key: str, current_balance: Dict):
        """显示余额变化

        逻辑说明：
        - quota: 可用余额
        - used: 已用额度
        - 账户总充值 = quota + used
        """
        if account_key not in self.last_balance_data:
            # 首次记录，不显示变化
            return

        last_balance = self.last_balance_data[account_key]
        last_quota = last_balance.get('quota', 0)  # 上次可用余额
        last_used = last_balance.get('used', 0)    # 上次已用
        current_quota = current_balance['quota']    # 当前可用余额
        current_used = current_balance['used']      # 当前已用

        # 计算总充值变化
        last_total = last_quota + last_used      # 上次总充值
        current_total = current_quota + current_used  # 当前总充值
        total_recharge = current_total - last_total   # 新充值金额

        # 计算消费变化
        used_change = current_used - last_used

        # 计算可用余额变化
        quota_change = current_quota - last_quota

        if total_recharge != 0 or used_change != 0:
            print(f'[CHANGE] 余额变更:')

            # 显示充值
            if total_recharge > 0:
                print(f'  💳 本期充值: +${total_recharge:.2f} (总充值: ${last_total:.2f} → ${current_total:.2f})')
            elif total_recharge < 0:
                print(f'  ⚠️  总充值减少: ${total_recharge:.2f} (${last_total:.2f} → ${current_total:.2f})')

            # 显示消费
            if used_change > 0:
                print(f'  📊 本期消费: +${used_change:.2f} (已用: ${last_used:.2f} → ${current_used:.2f})')
            elif used_change < 0:
                print(f'  🔄 已用减少: ${used_change:.2f} (${last_used:.2f} → ${current_used:.2f})')

            # 显示可用余额变化（净效果）
            if quota_change > 0:
                print(f'  💰 可用余额增加: +${quota_change:.2f} (${last_quota:.2f} → ${current_quota:.2f})')
            elif quota_change < 0:
                print(f'  💰 可用余额减少: ${quota_change:.2f} (${last_quota:.2f} → ${current_quota:.2f})')
            else:
                print(f'  ℹ️  可用余额不变: ${current_quota:.2f}')

    def _save_balance_hash(self, balance_hash: str):
        """保存余额哈希"""
        try:
            with open(BALANCE_HASH_FILE, 'w') as f:
                f.write(balance_hash)
        except Exception as e:
            print(f'[WARN] 保存余额哈希失败: {e}')

    def _generate_balance_hash(self, balances: Dict) -> str:
        """生成余额哈希"""
        simple_balances = {k: v['quota'] for k, v in balances.items()}
        balance_json = json.dumps(simple_balances, sort_keys=True)
        return hashlib.sha256(balance_json.encode()).hexdigest()[:16]

    def _check_balance_change(self):
        """检查余额是否变化"""
        if not self.current_balances:
            return

        current_hash = self._generate_balance_hash(self.current_balances)

        if self.last_balance_hash is None:
            # 首次运行
            self.balance_changed = True
            print('[INFO] 首次运行，记录当前余额')
        elif current_hash != self.last_balance_hash:
            # 余额变化
            self.balance_changed = True
            print('[INFO] 检测到余额变化')
        else:
            self.balance_changed = False
            print('[INFO] 余额无变化')

        # 保存新的哈希和余额数据
        self._save_balance_hash(current_hash)
        self._save_balance_data()

    def has_balance_changed(self) -> bool:
        """余额是否变化"""
        return self.balance_changed
