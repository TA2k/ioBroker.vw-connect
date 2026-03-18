.class public abstract synthetic Lx71/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I

.field public static final synthetic b:[I


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    invoke-static {}, Lx71/l;->values()[Lx71/l;

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
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x1

    .line 10
    :try_start_0
    sget-object v3, Lx71/l;->d:Lx71/l;

    .line 11
    .line 12
    aput v2, v0, v1
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    :catch_0
    const/4 v3, 0x2

    .line 15
    :try_start_1
    sget-object v4, Lx71/l;->d:Lx71/l;

    .line 16
    .line 17
    aput v3, v0, v2
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 18
    .line 19
    :catch_1
    const/4 v4, 0x3

    .line 20
    :try_start_2
    sget-object v5, Lx71/l;->d:Lx71/l;

    .line 21
    .line 22
    aput v4, v0, v3
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 23
    .line 24
    :catch_2
    const/4 v5, 0x4

    .line 25
    :try_start_3
    sget-object v6, Lx71/l;->d:Lx71/l;

    .line 26
    .line 27
    aput v5, v0, v4
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 28
    .line 29
    :catch_3
    sput-object v0, Lx71/b;->a:[I

    .line 30
    .line 31
    invoke-static {}, Lx71/a;->values()[Lx71/a;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    array-length v0, v0

    .line 36
    new-array v0, v0, [I

    .line 37
    .line 38
    :try_start_4
    sget-object v6, Lx71/a;->d:Lx71/a;

    .line 39
    .line 40
    aput v2, v0, v1
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 41
    .line 42
    :catch_4
    :try_start_5
    sget-object v1, Lx71/a;->d:Lx71/a;

    .line 43
    .line 44
    aput v3, v0, v2
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 45
    .line 46
    :catch_5
    :try_start_6
    sget-object v1, Lx71/a;->d:Lx71/a;

    .line 47
    .line 48
    aput v4, v0, v3
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 49
    .line 50
    :catch_6
    :try_start_7
    sget-object v1, Lx71/a;->d:Lx71/a;

    .line 51
    .line 52
    aput v5, v0, v4
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 53
    .line 54
    :catch_7
    sput-object v0, Lx71/b;->b:[I

    .line 55
    .line 56
    return-void
.end method
