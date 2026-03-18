.class public abstract synthetic Lb50/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    invoke-static {}, Lbl0/h0;->values()[Lbl0/h0;

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
    const/4 v2, 0x2

    .line 10
    :try_start_0
    sget-object v3, Lbl0/h0;->d:Lbl0/h0;

    .line 11
    .line 12
    aput v1, v0, v2
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    :catch_0
    :try_start_1
    sget-object v3, Lbl0/h0;->d:Lbl0/h0;

    .line 15
    .line 16
    aput v2, v0, v1
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 17
    .line 18
    :catch_1
    const/4 v1, 0x3

    .line 19
    const/4 v2, 0x4

    .line 20
    :try_start_2
    sget-object v3, Lbl0/h0;->d:Lbl0/h0;

    .line 21
    .line 22
    aput v1, v0, v2
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 23
    .line 24
    :catch_2
    :try_start_3
    sget-object v3, Lbl0/h0;->d:Lbl0/h0;

    .line 25
    .line 26
    aput v2, v0, v1
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 27
    .line 28
    :catch_3
    const/4 v1, 0x5

    .line 29
    :try_start_4
    sget-object v2, Lbl0/h0;->d:Lbl0/h0;

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    aput v1, v0, v2
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 33
    .line 34
    :catch_4
    const/4 v2, 0x6

    .line 35
    :try_start_5
    sget-object v3, Lbl0/h0;->d:Lbl0/h0;

    .line 36
    .line 37
    aput v2, v0, v1
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 38
    .line 39
    :catch_5
    :try_start_6
    sget-object v1, Lbl0/h0;->d:Lbl0/h0;

    .line 40
    .line 41
    const/4 v1, 0x7

    .line 42
    aput v1, v0, v1
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 43
    .line 44
    :catch_6
    :try_start_7
    sget-object v1, Lbl0/h0;->d:Lbl0/h0;

    .line 45
    .line 46
    const/16 v1, 0x8

    .line 47
    .line 48
    aput v1, v0, v2
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 49
    .line 50
    :catch_7
    sput-object v0, Lb50/e;->a:[I

    .line 51
    .line 52
    return-void
.end method
