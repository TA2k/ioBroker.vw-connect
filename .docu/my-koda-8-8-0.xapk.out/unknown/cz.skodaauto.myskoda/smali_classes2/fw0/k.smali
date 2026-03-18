.class public abstract Lfw0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lvw0/a;

.field public static final b:Lvw0/a;

.field public static final c:Llx0/q;

.field public static final d:Lgw0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2
    .line 3
    const-class v1, Llx0/b0;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v2, 0x0

    .line 10
    :try_start_0
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 11
    .line 12
    .line 13
    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-object v3, v2

    .line 16
    :goto_0
    new-instance v4, Lzw0/a;

    .line 17
    .line 18
    invoke-direct {v4, v0, v3}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Lvw0/a;

    .line 22
    .line 23
    const-string v3, "SkipSaveBody"

    .line 24
    .line 25
    invoke-direct {v0, v3, v4}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 26
    .line 27
    .line 28
    sput-object v0, Lfw0/k;->a:Lvw0/a;

    .line 29
    .line 30
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :try_start_1
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 37
    .line 38
    .line 39
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 40
    :catchall_1
    new-instance v1, Lzw0/a;

    .line 41
    .line 42
    invoke-direct {v1, v0, v2}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 43
    .line 44
    .line 45
    new-instance v0, Lvw0/a;

    .line 46
    .line 47
    const-string v2, "ResponseBodySaved"

    .line 48
    .line 49
    invoke-direct {v0, v2, v1}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 50
    .line 51
    .line 52
    sput-object v0, Lfw0/k;->b:Lvw0/a;

    .line 53
    .line 54
    new-instance v0, Lf2/h0;

    .line 55
    .line 56
    const/16 v1, 0x9

    .line 57
    .line 58
    invoke-direct {v0, v1}, Lf2/h0;-><init>(I)V

    .line 59
    .line 60
    .line 61
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Lfw0/k;->c:Llx0/q;

    .line 66
    .line 67
    new-instance v0, Lf31/n;

    .line 68
    .line 69
    const/16 v1, 0x18

    .line 70
    .line 71
    invoke-direct {v0, v1}, Lf31/n;-><init>(I)V

    .line 72
    .line 73
    .line 74
    new-instance v1, Lz81/g;

    .line 75
    .line 76
    const/4 v2, 0x2

    .line 77
    invoke-direct {v1, v2}, Lz81/g;-><init>(I)V

    .line 78
    .line 79
    .line 80
    const-string v2, "SaveBody"

    .line 81
    .line 82
    invoke-static {v2, v1, v0}, Lkp/q9;->a(Ljava/lang/String;Lay0/a;Lay0/k;)Lgw0/c;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    sput-object v0, Lfw0/k;->d:Lgw0/c;

    .line 87
    .line 88
    sget-object v0, Lfw0/j;->d:Lfw0/j;

    .line 89
    .line 90
    new-instance v1, Lf31/n;

    .line 91
    .line 92
    const/16 v2, 0x19

    .line 93
    .line 94
    invoke-direct {v1, v2}, Lf31/n;-><init>(I)V

    .line 95
    .line 96
    .line 97
    const-string v2, "DoubleReceivePlugin"

    .line 98
    .line 99
    invoke-static {v2, v0, v1}, Lkp/q9;->a(Ljava/lang/String;Lay0/a;Lay0/k;)Lgw0/c;

    .line 100
    .line 101
    .line 102
    return-void
.end method

.method public static final a()Lt21/b;
    .locals 1

    .line 1
    sget-object v0, Lfw0/k;->c:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lt21/b;

    .line 8
    .line 9
    return-object v0
.end method

.method public static final b(Law0/h;)Z
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Law0/h;->M()Law0/c;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Law0/c;->getAttributes()Lvw0/d;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const-string v0, "key"

    .line 18
    .line 19
    sget-object v1, Lfw0/k;->b:Lvw0/a;

    .line 20
    .line 21
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Lvw0/d;->c()Ljava/util/Map;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-interface {p0, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0
.end method
