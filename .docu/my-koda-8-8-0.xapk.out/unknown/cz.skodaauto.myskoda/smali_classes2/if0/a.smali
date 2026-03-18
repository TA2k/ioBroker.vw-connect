.class public abstract synthetic Lif0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I

.field public static final synthetic b:[I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    invoke-static {}, Lcz/myskoda/api/bff/v1/RenderModificationsDto$AnchorTo;->values()[Lcz/myskoda/api/bff/v1/RenderModificationsDto$AnchorTo;

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
    sget-object v2, Lcz/myskoda/api/bff/v1/RenderModificationsDto$AnchorTo;->RIGHT:Lcz/myskoda/api/bff/v1/RenderModificationsDto$AnchorTo;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    :catch_0
    :try_start_1
    sget-object v2, Lcz/myskoda/api/bff/v1/RenderModificationsDto$AnchorTo;->LEFT:Lcz/myskoda/api/bff/v1/RenderModificationsDto$AnchorTo;

    .line 18
    .line 19
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    const/4 v3, 0x2

    .line 24
    aput v3, v0, v2
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 25
    .line 26
    :catch_1
    :try_start_2
    sget-object v2, Lcz/myskoda/api/bff/v1/RenderModificationsDto$AnchorTo;->CENTER:Lcz/myskoda/api/bff/v1/RenderModificationsDto$AnchorTo;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    const/4 v3, 0x3

    .line 33
    aput v3, v0, v2
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 34
    .line 35
    :catch_2
    sput-object v0, Lif0/a;->a:[I

    .line 36
    .line 37
    invoke-static {}, Lss0/e;->values()[Lss0/e;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    array-length v0, v0

    .line 42
    new-array v0, v0, [I

    .line 43
    .line 44
    :try_start_3
    sget-object v2, Lss0/e;->d:Lss0/e;

    .line 45
    .line 46
    const/16 v2, 0x3f

    .line 47
    .line 48
    aput v1, v0, v2
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 49
    .line 50
    :catch_3
    sput-object v0, Lif0/a;->b:[I

    .line 51
    .line 52
    return-void
.end method
