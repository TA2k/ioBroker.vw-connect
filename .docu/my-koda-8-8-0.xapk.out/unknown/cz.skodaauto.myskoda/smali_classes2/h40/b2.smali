.class public abstract synthetic Lh40/b2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I

.field public static final synthetic b:[I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    invoke-static {}, Lg40/g0;->values()[Lg40/g0;

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
    :try_start_0
    sget-object v2, Lg40/g0;->d:Lg40/g0;

    .line 10
    .line 11
    aput v1, v0, v1
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    .line 13
    :catch_0
    sput-object v0, Lh40/b2;->a:[I

    .line 14
    .line 15
    invoke-static {}, Lh40/a2;->values()[Lh40/a2;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    array-length v0, v0

    .line 20
    new-array v0, v0, [I

    .line 21
    .line 22
    :try_start_1
    sget-object v2, Lh40/a2;->d:Lh40/a2;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    aput v1, v0, v2
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 26
    .line 27
    :catch_1
    sput-object v0, Lh40/b2;->b:[I

    .line 28
    .line 29
    return-void
.end method
