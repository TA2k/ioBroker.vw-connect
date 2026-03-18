.class public abstract synthetic Ltz/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    invoke-static {}, Lrd0/x;->values()[Lrd0/x;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v0, v0

    .line 6
    new-array v0, v0, [I

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x7

    .line 10
    :try_start_0
    sget-object v3, Lrd0/x;->d:Lrd0/x;

    .line 11
    .line 12
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    :catch_0
    const/4 v3, 0x5

    .line 15
    :try_start_1
    sget-object v4, Lrd0/x;->d:Lrd0/x;

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    aput v4, v0, v3
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 19
    .line 20
    :catch_1
    const/4 v4, 0x3

    .line 21
    :try_start_2
    sget-object v5, Lrd0/x;->d:Lrd0/x;

    .line 22
    .line 23
    const/16 v5, 0x8

    .line 24
    .line 25
    aput v4, v0, v5
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 26
    .line 27
    :catch_2
    const/4 v5, 0x6

    .line 28
    :try_start_3
    sget-object v6, Lrd0/x;->d:Lrd0/x;

    .line 29
    .line 30
    const/4 v6, 0x4

    .line 31
    aput v6, v0, v5
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 32
    .line 33
    :catch_3
    :try_start_4
    sget-object v6, Lrd0/x;->d:Lrd0/x;

    .line 34
    .line 35
    aput v3, v0, v4
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 36
    .line 37
    :catch_4
    :try_start_5
    sget-object v3, Lrd0/x;->d:Lrd0/x;

    .line 38
    .line 39
    aput v5, v0, v1
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 40
    .line 41
    :catch_5
    :try_start_6
    sget-object v1, Lrd0/x;->d:Lrd0/x;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    aput v2, v0, v1
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 45
    .line 46
    :catch_6
    sput-object v0, Ltz/j;->a:[I

    .line 47
    .line 48
    return-void
.end method
