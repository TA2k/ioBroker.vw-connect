.class public final Lxw/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxw/j;


# static fields
.field public static final d:Lxw/c;

.field public static final e:Lxw/c;

.field public static final f:Lxw/c;

.field public static final g:Lxw/c;

.field public static final h:Lxw/a;

.field public static final i:Lxw/a;

.field public static final j:Lxw/a;

.field public static final k:Lxw/a;

.field public static final l:Lxw/a;

.field public static final m:Lxw/a;

.field public static final n:Lxw/a;

.field public static final o:Lxw/a;

.field public static final p:Lxw/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lxw/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lxw/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lxw/e;->d:Lxw/c;

    .line 8
    .line 9
    new-instance v0, Lxw/c;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lxw/c;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lxw/e;->e:Lxw/c;

    .line 16
    .line 17
    new-instance v0, Lxw/c;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Lxw/c;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lxw/e;->f:Lxw/c;

    .line 24
    .line 25
    new-instance v0, Lxw/c;

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    invoke-direct {v0, v1}, Lxw/c;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lxw/e;->g:Lxw/c;

    .line 32
    .line 33
    new-instance v0, Lxw/a;

    .line 34
    .line 35
    const/4 v1, 0x5

    .line 36
    invoke-direct {v0, v1}, Lxw/a;-><init>(I)V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lxw/e;->h:Lxw/a;

    .line 40
    .line 41
    new-instance v0, Lxw/a;

    .line 42
    .line 43
    const/4 v1, 0x6

    .line 44
    invoke-direct {v0, v1}, Lxw/a;-><init>(I)V

    .line 45
    .line 46
    .line 47
    sput-object v0, Lxw/e;->i:Lxw/a;

    .line 48
    .line 49
    new-instance v0, Lxw/a;

    .line 50
    .line 51
    const/4 v1, 0x7

    .line 52
    invoke-direct {v0, v1}, Lxw/a;-><init>(I)V

    .line 53
    .line 54
    .line 55
    sput-object v0, Lxw/e;->j:Lxw/a;

    .line 56
    .line 57
    new-instance v0, Lxw/a;

    .line 58
    .line 59
    const/16 v1, 0x8

    .line 60
    .line 61
    invoke-direct {v0, v1}, Lxw/a;-><init>(I)V

    .line 62
    .line 63
    .line 64
    sput-object v0, Lxw/e;->k:Lxw/a;

    .line 65
    .line 66
    new-instance v0, Lxw/a;

    .line 67
    .line 68
    const/4 v1, 0x0

    .line 69
    invoke-direct {v0, v1}, Lxw/a;-><init>(I)V

    .line 70
    .line 71
    .line 72
    sput-object v0, Lxw/e;->l:Lxw/a;

    .line 73
    .line 74
    new-instance v0, Lxw/a;

    .line 75
    .line 76
    const/4 v1, 0x1

    .line 77
    invoke-direct {v0, v1}, Lxw/a;-><init>(I)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Lxw/e;->m:Lxw/a;

    .line 81
    .line 82
    new-instance v0, Lxw/a;

    .line 83
    .line 84
    const/4 v1, 0x2

    .line 85
    invoke-direct {v0, v1}, Lxw/a;-><init>(I)V

    .line 86
    .line 87
    .line 88
    sput-object v0, Lxw/e;->n:Lxw/a;

    .line 89
    .line 90
    new-instance v0, Lxw/a;

    .line 91
    .line 92
    const/4 v1, 0x3

    .line 93
    invoke-direct {v0, v1}, Lxw/a;-><init>(I)V

    .line 94
    .line 95
    .line 96
    sput-object v0, Lxw/e;->o:Lxw/a;

    .line 97
    .line 98
    new-instance v0, Lxw/a;

    .line 99
    .line 100
    const/4 v1, 0x4

    .line 101
    invoke-direct {v0, v1}, Lxw/a;-><init>(I)V

    .line 102
    .line 103
    .line 104
    sput-object v0, Lxw/e;->p:Lxw/a;

    .line 105
    .line 106
    return-void
.end method

.method public static b(Ljava/util/LinkedHashSet;Ljava/lang/Class;Z)V
    .locals 3

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Class;->getInterfaces()[Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    array-length p2, p1

    .line 11
    const/4 v0, 0x0

    .line 12
    :goto_0
    if-ge v0, p2, :cond_1

    .line 13
    .line 14
    aget-object v1, p1, v0

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    invoke-static {p0, v1, v2}, Lxw/e;->b(Ljava/util/LinkedHashSet;Ljava/lang/Class;Z)V

    .line 18
    .line 19
    .line 20
    add-int/lit8 v0, v0, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    return-void
.end method

.method public static c(Ljava/lang/Object;)Lxw/a;
    .locals 1

    .line 1
    instance-of v0, p0, [Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lxw/e;->h:Lxw/a;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    instance-of v0, p0, [Z

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    sget-object p0, Lxw/e;->i:Lxw/a;

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_1
    instance-of v0, p0, [B

    .line 16
    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    sget-object p0, Lxw/e;->j:Lxw/a;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_2
    instance-of v0, p0, [C

    .line 23
    .line 24
    if-eqz v0, :cond_3

    .line 25
    .line 26
    sget-object p0, Lxw/e;->k:Lxw/a;

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_3
    instance-of v0, p0, [S

    .line 30
    .line 31
    if-eqz v0, :cond_4

    .line 32
    .line 33
    sget-object p0, Lxw/e;->l:Lxw/a;

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_4
    instance-of v0, p0, [I

    .line 37
    .line 38
    if-eqz v0, :cond_5

    .line 39
    .line 40
    sget-object p0, Lxw/e;->m:Lxw/a;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_5
    instance-of v0, p0, [J

    .line 44
    .line 45
    if-eqz v0, :cond_6

    .line 46
    .line 47
    sget-object p0, Lxw/e;->n:Lxw/a;

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_6
    instance-of v0, p0, [F

    .line 51
    .line 52
    if-eqz v0, :cond_7

    .line 53
    .line 54
    sget-object p0, Lxw/e;->o:Lxw/a;

    .line 55
    .line 56
    return-object p0

    .line 57
    :cond_7
    instance-of p0, p0, [D

    .line 58
    .line 59
    if-eqz p0, :cond_8

    .line 60
    .line 61
    sget-object p0, Lxw/e;->p:Lxw/a;

    .line 62
    .line 63
    return-object p0

    .line 64
    :cond_8
    const/4 p0, 0x0

    .line 65
    return-object p0
.end method

.method public static e(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;
    .locals 2

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    .line 15
    :cond_0
    return-object v0

    .line 16
    :catch_0
    invoke-virtual {p0}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const-class v1, Ljava/lang/Object;

    .line 21
    .line 22
    if-eq v0, v1, :cond_1

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-static {p0, p1}, Lxw/e;->e(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :cond_1
    const/4 p0, 0x0

    .line 36
    return-object p0
.end method

.method public static f(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Method;
    .locals 7

    .line 1
    sget-object v0, Ljava/lang/Void;->TYPE:Ljava/lang/Class;

    .line 2
    .line 3
    const-string v1, "is"

    .line 4
    .line 5
    const-string v2, "get"

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    const/4 v4, 0x0

    .line 9
    :try_start_0
    invoke-virtual {p0, p1, v4}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    invoke-virtual {v5}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    move-result-object v6

    .line 17
    invoke-virtual {v6, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v6

    .line 21
    if-nez v6, :cond_1

    .line 22
    .line 23
    invoke-virtual {v5}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    if-nez v6, :cond_0

    .line 28
    .line 29
    invoke-virtual {v5, v3}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 30
    .line 31
    .line 32
    :cond_0
    return-object v5

    .line 33
    :catch_0
    :cond_1
    new-instance v5, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 36
    .line 37
    .line 38
    const/4 v6, 0x0

    .line 39
    invoke-virtual {p1, v6}, Ljava/lang/String;->charAt(I)C

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    invoke-static {v6}, Ljava/lang/Character;->toUpperCase(C)C

    .line 44
    .line 45
    .line 46
    move-result v6

    .line 47
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-virtual {v5, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    :try_start_1
    new-instance v5, Ljava/lang/StringBuilder;

    .line 62
    .line 63
    invoke-direct {v5, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v5, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    invoke-virtual {p0, v2, v4}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    invoke-virtual {v2}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    invoke-virtual {v5, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    if-nez v0, :cond_3

    .line 86
    .line 87
    invoke-virtual {v2}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-nez v0, :cond_2

    .line 92
    .line 93
    invoke-virtual {v2, v3}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 94
    .line 95
    .line 96
    :cond_2
    return-object v2

    .line 97
    :catch_1
    :cond_3
    :try_start_2
    new-instance v0, Ljava/lang/StringBuilder;

    .line 98
    .line 99
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    invoke-virtual {p0, p1, v4}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    invoke-virtual {p0}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    sget-object v0, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 118
    .line 119
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result p1

    .line 123
    if-nez p1, :cond_4

    .line 124
    .line 125
    invoke-virtual {p0}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    const-class v0, Ljava/lang/Boolean;

    .line 130
    .line 131
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result p1

    .line 135
    if-eqz p1, :cond_6

    .line 136
    .line 137
    :cond_4
    invoke-virtual {p0}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 138
    .line 139
    .line 140
    move-result p1

    .line 141
    if-nez p1, :cond_5

    .line 142
    .line 143
    invoke-virtual {p0, v3}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 144
    .line 145
    .line 146
    :cond_5
    return-object p0

    .line 147
    :catch_2
    :cond_6
    return-object v4
.end method


# virtual methods
.method public a(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    return-object p1
.end method

.method public d(Ljava/lang/Object;Ljava/lang/String;)Lxw/p;
    .locals 4

    .line 1
    sget-object p0, Lxw/v;->e:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x0

    .line 5
    if-eq p2, p0, :cond_5

    .line 6
    .line 7
    sget-object p0, Lxw/v;->f:Ljava/lang/String;

    .line 8
    .line 9
    if-ne p2, p0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    instance-of p0, p1, Ljava/util/Map;

    .line 13
    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    sget-object p0, Lxw/e;->d:Lxw/c;

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    invoke-virtual {p2, v0}, Ljava/lang/String;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    const/16 v2, 0x30

    .line 24
    .line 25
    if-lt p0, v2, :cond_4

    .line 26
    .line 27
    const/16 v2, 0x39

    .line 28
    .line 29
    if-gt p0, v2, :cond_4

    .line 30
    .line 31
    instance-of p0, p1, Ljava/util/List;

    .line 32
    .line 33
    if-eqz p0, :cond_2

    .line 34
    .line 35
    sget-object p0, Lxw/e;->e:Lxw/c;

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_2
    instance-of p0, p1, Ljava/util/Iterator;

    .line 39
    .line 40
    if-eqz p0, :cond_3

    .line 41
    .line 42
    sget-object p0, Lxw/e;->f:Lxw/c;

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-virtual {p0}, Ljava/lang/Class;->isArray()Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-eqz p0, :cond_4

    .line 54
    .line 55
    invoke-static {p1}, Lxw/e;->c(Ljava/lang/Object;)Lxw/a;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    goto :goto_1

    .line 60
    :cond_4
    move-object p0, v1

    .line 61
    goto :goto_1

    .line 62
    :cond_5
    :goto_0
    sget-object p0, Lxw/e;->g:Lxw/c;

    .line 63
    .line 64
    :goto_1
    if-eqz p0, :cond_6

    .line 65
    .line 66
    return-object p0

    .line 67
    :cond_6
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    move-object p1, p0

    .line 72
    :goto_2
    const-class v2, Ljava/lang/Object;

    .line 73
    .line 74
    if-eqz p1, :cond_8

    .line 75
    .line 76
    if-eq p1, v2, :cond_8

    .line 77
    .line 78
    invoke-static {p1, p2}, Lxw/e;->f(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Method;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    if-eqz v3, :cond_7

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_7
    invoke-virtual {p1}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    goto :goto_2

    .line 90
    :cond_8
    move-object v3, v1

    .line 91
    :goto_3
    if-eqz v3, :cond_9

    .line 92
    .line 93
    new-instance p0, Lxw/d;

    .line 94
    .line 95
    const/4 p1, 0x0

    .line 96
    invoke-direct {p0, v3, p1}, Lxw/d;-><init>(Ljava/lang/reflect/AccessibleObject;I)V

    .line 97
    .line 98
    .line 99
    return-object p0

    .line 100
    :cond_9
    invoke-static {p0, p2}, Lxw/e;->e(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    if-eqz p1, :cond_a

    .line 105
    .line 106
    new-instance p0, Lxw/d;

    .line 107
    .line 108
    const/4 p2, 0x2

    .line 109
    invoke-direct {p0, p1, p2}, Lxw/d;-><init>(Ljava/lang/reflect/AccessibleObject;I)V

    .line 110
    .line 111
    .line 112
    return-object p0

    .line 113
    :cond_a
    new-instance p1, Ljava/util/LinkedHashSet;

    .line 114
    .line 115
    invoke-direct {p1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 116
    .line 117
    .line 118
    :goto_4
    if-eqz p0, :cond_b

    .line 119
    .line 120
    if-eq p0, v2, :cond_b

    .line 121
    .line 122
    invoke-static {p1, p0, v0}, Lxw/e;->b(Ljava/util/LinkedHashSet;Ljava/lang/Class;Z)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {p0}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    goto :goto_4

    .line 130
    :cond_b
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    :cond_c
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    if-eqz p1, :cond_d

    .line 139
    .line 140
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    check-cast p1, Ljava/lang/Class;

    .line 145
    .line 146
    invoke-static {p1, p2}, Lxw/e;->f(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Method;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    if-eqz p1, :cond_c

    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_d
    move-object p1, v1

    .line 154
    :goto_5
    if-eqz p1, :cond_e

    .line 155
    .line 156
    new-instance p0, Lxw/d;

    .line 157
    .line 158
    const/4 p2, 0x1

    .line 159
    invoke-direct {p0, p1, p2}, Lxw/d;-><init>(Ljava/lang/reflect/AccessibleObject;I)V

    .line 160
    .line 161
    .line 162
    return-object p0

    .line 163
    :cond_e
    return-object v1
.end method

.method public g(Ljava/lang/Object;)Ljava/util/Iterator;
    .locals 1

    .line 1
    instance-of p0, p1, Ljava/lang/Iterable;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    check-cast p1, Ljava/lang/Iterable;

    .line 6
    .line 7
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    instance-of p0, p1, Ljava/util/Iterator;

    .line 13
    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    check-cast p1, Ljava/util/Iterator;

    .line 17
    .line 18
    return-object p1

    .line 19
    :cond_1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {p0}, Ljava/lang/Class;->isArray()Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz p0, :cond_2

    .line 28
    .line 29
    invoke-static {p1}, Lxw/e;->c(Ljava/lang/Object;)Lxw/a;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    new-instance v0, Lxw/b;

    .line 34
    .line 35
    invoke-direct {v0, p0, p1}, Lxw/b;-><init>(Lxw/a;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :cond_2
    const/4 p0, 0x0

    .line 40
    return-object p0
.end method
