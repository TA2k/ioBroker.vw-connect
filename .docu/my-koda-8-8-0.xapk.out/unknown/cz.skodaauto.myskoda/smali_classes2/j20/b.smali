.class public abstract synthetic Lj20/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    invoke-static {}, Lss0/n;->values()[Lss0/n;

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
    sget-object v2, Lss0/n;->d:Lss0/n;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    :catch_0
    const/4 v2, 0x2

    .line 15
    :try_start_1
    sget-object v3, Lss0/n;->d:Lss0/n;

    .line 16
    .line 17
    aput v2, v0, v1
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 18
    .line 19
    :catch_1
    const/4 v1, 0x3

    .line 20
    :try_start_2
    sget-object v3, Lss0/n;->d:Lss0/n;

    .line 21
    .line 22
    aput v1, v0, v2
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 23
    .line 24
    :catch_2
    const/4 v2, 0x4

    .line 25
    :try_start_3
    sget-object v3, Lss0/n;->d:Lss0/n;

    .line 26
    .line 27
    aput v2, v0, v1
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 28
    .line 29
    :catch_3
    :try_start_4
    sget-object v1, Lss0/n;->d:Lss0/n;

    .line 30
    .line 31
    const/4 v1, 0x5

    .line 32
    aput v1, v0, v2
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 33
    .line 34
    :catch_4
    sput-object v0, Lj20/b;->a:[I

    .line 35
    .line 36
    return-void
.end method
