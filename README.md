# fairyMountain
种源-仙山后端

20230110 开发登录系统，先做微信小程序的登录，通过SpringSecurity获取授权

## 登录

登录有两种通道，如果通过账号密码注册则直接通过JwtLoginFilter，如果使用微信一键登录则通过AdminController

### 微信登录思路

​	微信登录被设计成了一个普通的Controller，当wx小程序端点击一键登录时（调用wx.login）则发送key给后端，后端存储到redis中并返回前端key，当小程序端点击授权时，小程序同时把key secret等信息全部发送给后端，后端验证后登录成功。判断是否为第一次登录，第一次登录则把信息放入数据库，此操作为了将来多种平台共存时登录。

​	权限模型使用RBAC1，数据库中建立5个表，用户 角色 权限 用户角色关系 角色权限关系，一个用户只能为一个角色，角色可以继承，子角色有父角色所有权限。
    在tokenUtils通过查询数据库角色权限信息配置用户权限，现在先不写，默认拥有全部权限
微信小程序是可以自动获取手机号的，这个以后再写

学习一下Mybatis-plus 新的join功能

class test {
@Resource
private UserMapper userMapper;

    void testJoin() {
        List<UserDTO> list = userMapper.selectJoinList(UserDTO.class,
                new MPJLambdaWrapper<UserDO>()
                        .selectAll(UserDO.class)
                        .select(UserAddressDO::getTel)
                        .selectAs(UserAddressDO::getAddress, UserDTO::getUserAddress)
                        .select(AreaDO::getProvince, AreaDO::getCity)
                        .leftJoin(UserAddressDO.class, UserAddressDO::getUserId, UserDO::getId)
                        .leftJoin(AreaDO.class, AreaDO::getId, UserAddressDO::getAreaId)
                        .eq(UserDO::getId, 1)
                        .like(UserAddressDO::getTel, "1")
                        .gt(UserDO::getId, 5));
    }
}


SELECT
t.id,
t.name,
t.sex,
t.head_img,
t1.tel,
t1.address AS userAddress,
t2.province,
t2.city
FROM
user t
LEFT JOIN user_address t1 ON t1.user_id = t.id
LEFT JOIN area t2 ON t2.id = t1.area_id
WHERE (
t.id = ?
AND t1.tel LIKE ?
AND t.id > ?)
