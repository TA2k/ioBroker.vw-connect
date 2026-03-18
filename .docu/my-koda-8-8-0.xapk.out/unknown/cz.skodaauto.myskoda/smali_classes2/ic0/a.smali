.class public final Lic0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lic0/d;

.field public final b:Lxl0/f;

.field public final c:Lti0/a;

.field public final d:Lxl0/g;

.field public final e:Ljava/util/EnumMap;

.field public final f:Ljava/util/EnumMap;

.field public final g:Ljava/util/HashMap;

.field public final h:Lyy0/q1;

.field public final i:Lyy0/k1;


# direct methods
.method public constructor <init>(Lic0/d;Lxl0/f;Lti0/a;Lxl0/g;)V
    .locals 3

    .line 1
    new-instance v0, Ljava/util/EnumMap;

    .line 2
    .line 3
    const-class v1, Llc0/l;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/EnumMap;-><init>(Ljava/lang/Class;)V

    .line 6
    .line 7
    .line 8
    new-instance v2, Ljava/util/EnumMap;

    .line 9
    .line 10
    invoke-direct {v2, v1}, Ljava/util/EnumMap;-><init>(Ljava/lang/Class;)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lic0/a;->a:Lic0/d;

    .line 17
    .line 18
    iput-object p2, p0, Lic0/a;->b:Lxl0/f;

    .line 19
    .line 20
    iput-object p3, p0, Lic0/a;->c:Lti0/a;

    .line 21
    .line 22
    iput-object p4, p0, Lic0/a;->d:Lxl0/g;

    .line 23
    .line 24
    iput-object v0, p0, Lic0/a;->e:Ljava/util/EnumMap;

    .line 25
    .line 26
    iput-object v2, p0, Lic0/a;->f:Ljava/util/EnumMap;

    .line 27
    .line 28
    new-instance p1, Ljava/util/HashMap;

    .line 29
    .line 30
    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lic0/a;->g:Ljava/util/HashMap;

    .line 34
    .line 35
    const/4 p1, 0x0

    .line 36
    const/4 p2, 0x5

    .line 37
    const/4 p3, 0x1

    .line 38
    invoke-static {p3, p2, p1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iput-object p1, p0, Lic0/a;->h:Lyy0/q1;

    .line 43
    .line 44
    new-instance p2, Lyy0/k1;

    .line 45
    .line 46
    invoke-direct {p2, p1}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 47
    .line 48
    .line 49
    iput-object p2, p0, Lic0/a;->i:Lyy0/k1;

    .line 50
    .line 51
    return-void
.end method

.method public static a(Llc0/l;Lcm0/b;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 v0, 0x1

    .line 6
    if-eqz p0, :cond_1

    .line 7
    .line 8
    if-ne p0, v0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    new-instance p0, La8/r0;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 14
    .line 15
    .line 16
    throw p0

    .line 17
    :cond_1
    :goto_0
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_4

    .line 22
    .line 23
    if-eq p0, v0, :cond_4

    .line 24
    .line 25
    const/4 p1, 0x2

    .line 26
    if-eq p0, p1, :cond_3

    .line 27
    .line 28
    const/4 p1, 0x3

    .line 29
    if-eq p0, p1, :cond_3

    .line 30
    .line 31
    const/4 p1, 0x4

    .line 32
    if-ne p0, p1, :cond_2

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_2
    new-instance p0, La8/r0;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_3
    :goto_1
    const-string p0, "4fffed6b-815a-4b6f-af4a-b0ccccb4ff6d@apps_vw-dilab_com"

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_4
    const-string p0, "7f045eee-7003-4379-9968-9355ed2adb06@apps_vw-dilab_com"

    .line 45
    .line 46
    return-object p0
.end method

.method public static b(Llc0/l;)Ljava/lang/String;
    .locals 15

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-ne p0, v0, :cond_0

    .line 9
    .line 10
    const-string p0, "openid"

    .line 11
    .line 12
    const-string v0, "delete"

    .line 13
    .line 14
    filled-new-array {p0, v0}, [Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, La8/r0;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    const-string v13, "profile"

    .line 30
    .line 31
    const-string v14, "vin"

    .line 32
    .line 33
    const-string v0, "address"

    .line 34
    .line 35
    const-string v1, "badge"

    .line 36
    .line 37
    const-string v2, "birthdate"

    .line 38
    .line 39
    const-string v3, "cars"

    .line 40
    .line 41
    const-string v4, "driversLicense"

    .line 42
    .line 43
    const-string v5, "dealers"

    .line 44
    .line 45
    const-string v6, "email"

    .line 46
    .line 47
    const-string v7, "mileage"

    .line 48
    .line 49
    const-string v8, "mbb"

    .line 50
    .line 51
    const-string v9, "nationalIdentifier"

    .line 52
    .line 53
    const-string v10, "openid"

    .line 54
    .line 55
    const-string v11, "phone"

    .line 56
    .line 57
    const-string v12, "profession"

    .line 58
    .line 59
    filled-new-array/range {v0 .. v14}, [Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    :goto_0
    move-object v0, p0

    .line 68
    check-cast v0, Ljava/lang/Iterable;

    .line 69
    .line 70
    const/4 v4, 0x0

    .line 71
    const/16 v5, 0x3e

    .line 72
    .line 73
    const-string v1, " "

    .line 74
    .line 75
    const/4 v2, 0x0

    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0
.end method
