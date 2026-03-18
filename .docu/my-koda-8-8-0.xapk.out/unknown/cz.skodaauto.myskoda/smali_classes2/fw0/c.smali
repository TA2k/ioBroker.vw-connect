.class public abstract Lfw0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lvw0/a;

.field public static final b:Lvw0/a;

.field public static final c:Lgw0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2
    .line 3
    const-class v1, Lbw0/a;

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
    const-string v3, "UploadProgressListenerAttributeKey"

    .line 24
    .line 25
    invoke-direct {v0, v3, v4}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 26
    .line 27
    .line 28
    sput-object v0, Lfw0/c;->a:Lvw0/a;

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
    const-string v2, "DownloadProgressListenerAttributeKey"

    .line 48
    .line 49
    invoke-direct {v0, v2, v1}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 50
    .line 51
    .line 52
    sput-object v0, Lfw0/c;->b:Lvw0/a;

    .line 53
    .line 54
    new-instance v0, Lf31/n;

    .line 55
    .line 56
    const/16 v1, 0x16

    .line 57
    .line 58
    invoke-direct {v0, v1}, Lf31/n;-><init>(I)V

    .line 59
    .line 60
    .line 61
    new-instance v1, Lz81/g;

    .line 62
    .line 63
    const/4 v2, 0x2

    .line 64
    invoke-direct {v1, v2}, Lz81/g;-><init>(I)V

    .line 65
    .line 66
    .line 67
    const-string v2, "BodyProgress"

    .line 68
    .line 69
    invoke-static {v2, v1, v0}, Lkp/q9;->a(Ljava/lang/String;Lay0/a;Lay0/k;)Lgw0/c;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    sput-object v0, Lfw0/c;->c:Lgw0/c;

    .line 74
    .line 75
    return-void
.end method
