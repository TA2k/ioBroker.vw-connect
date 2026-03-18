.class public abstract synthetic Leh0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    invoke-static {}, Ldh0/a;->values()[Ldh0/a;

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
    sget-object v1, Ldh0/a;->e:Ldh0/a;

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    const/4 v2, 0x1

    .line 12
    aput v2, v0, v1
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    :catch_0
    sput-object v0, Leh0/a;->a:[I

    .line 15
    .line 16
    return-void
.end method
