.class public abstract synthetic Ltz/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    invoke-static {}, Lcn0/a;->values()[Lcn0/a;

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
    :try_start_0
    sget-object v1, Lcn0/a;->d:Lcn0/a;

    .line 9
    .line 10
    const/16 v1, 0x15

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    aput v2, v0, v1
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    :catch_0
    :try_start_1
    sget-object v1, Lcn0/a;->d:Lcn0/a;

    .line 16
    .line 17
    const/16 v1, 0xa

    .line 18
    .line 19
    const/4 v2, 0x2

    .line 20
    aput v2, v0, v1
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 21
    .line 22
    :catch_1
    :try_start_2
    sget-object v1, Lcn0/a;->d:Lcn0/a;

    .line 23
    .line 24
    const/16 v1, 0xd

    .line 25
    .line 26
    const/4 v2, 0x3

    .line 27
    aput v2, v0, v1
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 28
    .line 29
    :catch_2
    sput-object v0, Ltz/g0;->a:[I

    .line 30
    .line 31
    return-void
.end method
