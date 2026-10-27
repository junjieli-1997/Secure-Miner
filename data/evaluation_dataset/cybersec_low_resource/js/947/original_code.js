    },
    
    //密码验证
    passwordVali: function (str) {
        return (str.length >= 8 && str.length<= 20);
    },
    
    //再次输入的密码验证
    repasswordVali: function (str, id) {
        var password = document.querySelector("#" + id).value;
        return (str === password);
    },
    
    // 判断是否为邮箱地址
    // 第一部分：由字母、数字、下划线、短线“-”、点号“.”组成，
    // 第二部分：为一个域名，域名由字母、数字、短线“-”、域名后缀组成，
    // 而域名后缀一般为.xxx或.xxx.xx，一区的域名后缀一般为2-4位，如cn,com,net，现在域名有的也会大于4位
    emailVali: function (str) {
        var regex = /^([\w-*\.*]+)@([\w-]+)((\.[\w-]{2,4}){1,2})$/;
        return regex.test(str);