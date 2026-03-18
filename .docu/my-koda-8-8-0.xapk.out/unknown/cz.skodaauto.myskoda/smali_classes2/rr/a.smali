.class public final Lrr/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Ljava/util/logging/Logger;

.field public static final d:Ljava/util/ArrayList;

.field public static final e:Lrr/a;

.field public static final f:Lrr/a;


# instance fields
.field public final a:Lrr/b;

.field public final b:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    const-class v0, Lrr/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lrr/a;->c:Ljava/util/logging/Logger;

    .line 12
    .line 13
    :try_start_0
    const-string v0, "android.app.Application"

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-static {v0, v2, v1}, Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    const-string v0, "GmsCore_OpenSSL"

    .line 21
    .line 22
    const-string v1, "AndroidOpenSSL"

    .line 23
    .line 24
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    new-instance v1, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 31
    .line 32
    .line 33
    :goto_0
    const/4 v3, 0x2

    .line 34
    if-ge v2, v3, :cond_1

    .line 35
    .line 36
    aget-object v3, v0, v2

    .line 37
    .line 38
    invoke-static {v3}, Ljava/security/Security;->getProvider(Ljava/lang/String;)Ljava/security/Provider;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    if-eqz v4, :cond_0

    .line 43
    .line 44
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_0
    sget-object v4, Lrr/a;->c:Ljava/util/logging/Logger;

    .line 49
    .line 50
    new-instance v5, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v6, "Provider "

    .line 53
    .line 54
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v3, " not available"

    .line 61
    .line 62
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    invoke-virtual {v4, v3}, Ljava/util/logging/Logger;->info(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_1
    sput-object v1, Lrr/a;->d:Ljava/util/ArrayList;

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :catch_0
    new-instance v0, Ljava/util/ArrayList;

    .line 79
    .line 80
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 81
    .line 82
    .line 83
    sput-object v0, Lrr/a;->d:Ljava/util/ArrayList;

    .line 84
    .line 85
    :goto_2
    new-instance v0, Lrr/a;

    .line 86
    .line 87
    new-instance v1, Lst/b;

    .line 88
    .line 89
    const/16 v2, 0xc

    .line 90
    .line 91
    invoke-direct {v1, v2}, Lst/b;-><init>(I)V

    .line 92
    .line 93
    .line 94
    invoke-direct {v0, v1}, Lrr/a;-><init>(Lrr/b;)V

    .line 95
    .line 96
    .line 97
    sput-object v0, Lrr/a;->e:Lrr/a;

    .line 98
    .line 99
    new-instance v0, Lrr/a;

    .line 100
    .line 101
    new-instance v1, Lwe0/b;

    .line 102
    .line 103
    invoke-direct {v1, v2}, Lwe0/b;-><init>(I)V

    .line 104
    .line 105
    .line 106
    invoke-direct {v0, v1}, Lrr/a;-><init>(Lrr/b;)V

    .line 107
    .line 108
    .line 109
    sput-object v0, Lrr/a;->f:Lrr/a;

    .line 110
    .line 111
    return-void
.end method

.method public constructor <init>(Lrr/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrr/a;->a:Lrr/b;

    .line 5
    .line 6
    sget-object p1, Lrr/a;->d:Ljava/util/ArrayList;

    .line 7
    .line 8
    iput-object p1, p0, Lrr/a;->b:Ljava/util/List;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lrr/a;->b:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    move-object v2, v1

    .line 9
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    iget-object v4, p0, Lrr/a;->a:Lrr/b;

    .line 14
    .line 15
    if-eqz v3, :cond_1

    .line 16
    .line 17
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    check-cast v3, Ljava/security/Provider;

    .line 22
    .line 23
    :try_start_0
    invoke-interface {v4, p1, v3}, Lrr/b;->b(Ljava/lang/String;Ljava/security/Provider;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    return-object p0

    .line 28
    :catch_0
    move-exception v3

    .line 29
    if-nez v2, :cond_0

    .line 30
    .line 31
    move-object v2, v3

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    invoke-interface {v4, p1, v1}, Lrr/b;->b(Ljava/lang/String;Ljava/security/Provider;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method
