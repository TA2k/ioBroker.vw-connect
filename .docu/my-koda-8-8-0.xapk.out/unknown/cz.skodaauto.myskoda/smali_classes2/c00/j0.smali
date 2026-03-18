.class public abstract synthetic Lc00/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    invoke-static {}, Lmb0/i;->values()[Lmb0/i;

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
    aput v2, v0, v1
    :try_end_0
    .catch Ljava/lang/NoSuchFieldError; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    .line 12
    :catch_0
    const/4 v3, 0x2

    .line 13
    :try_start_1
    sget-object v4, Lmb0/i;->d:Lmb0/i;

    .line 14
    .line 15
    aput v3, v0, v2
    :try_end_1
    .catch Ljava/lang/NoSuchFieldError; {:try_start_1 .. :try_end_1} :catch_1

    .line 16
    .line 17
    :catch_1
    sput-object v0, Lc00/j0;->a:[I

    .line 18
    .line 19
    invoke-static {}, Lmb0/e;->values()[Lmb0/e;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    array-length v0, v0

    .line 24
    new-array v0, v0, [I

    .line 25
    .line 26
    :try_start_2
    aput v2, v0, v2
    :try_end_2
    .catch Ljava/lang/NoSuchFieldError; {:try_start_2 .. :try_end_2} :catch_2

    .line 27
    .line 28
    :catch_2
    const/4 v4, 0x4

    .line 29
    :try_start_3
    sget-object v5, Lmb0/e;->d:Lmb0/e;

    .line 30
    .line 31
    aput v3, v0, v4
    :try_end_3
    .catch Ljava/lang/NoSuchFieldError; {:try_start_3 .. :try_end_3} :catch_3

    .line 32
    .line 33
    :catch_3
    const/4 v5, 0x3

    .line 34
    :try_start_4
    sget-object v6, Lmb0/e;->d:Lmb0/e;

    .line 35
    .line 36
    aput v5, v0, v3
    :try_end_4
    .catch Ljava/lang/NoSuchFieldError; {:try_start_4 .. :try_end_4} :catch_4

    .line 37
    .line 38
    :catch_4
    :try_start_5
    sget-object v6, Lmb0/e;->d:Lmb0/e;

    .line 39
    .line 40
    aput v4, v0, v5
    :try_end_5
    .catch Ljava/lang/NoSuchFieldError; {:try_start_5 .. :try_end_5} :catch_5

    .line 41
    .line 42
    :catch_5
    const/4 v6, 0x5

    .line 43
    :try_start_6
    sget-object v7, Lmb0/e;->d:Lmb0/e;

    .line 44
    .line 45
    aput v6, v0, v1
    :try_end_6
    .catch Ljava/lang/NoSuchFieldError; {:try_start_6 .. :try_end_6} :catch_6

    .line 46
    .line 47
    :catch_6
    const/4 v7, 0x6

    .line 48
    :try_start_7
    sget-object v8, Lmb0/e;->d:Lmb0/e;

    .line 49
    .line 50
    aput v7, v0, v6
    :try_end_7
    .catch Ljava/lang/NoSuchFieldError; {:try_start_7 .. :try_end_7} :catch_7

    .line 51
    .line 52
    :catch_7
    const/4 v8, 0x7

    .line 53
    :try_start_8
    sget-object v9, Lmb0/e;->d:Lmb0/e;

    .line 54
    .line 55
    aput v8, v0, v7
    :try_end_8
    .catch Ljava/lang/NoSuchFieldError; {:try_start_8 .. :try_end_8} :catch_8

    .line 56
    .line 57
    :catch_8
    const/16 v7, 0x8

    .line 58
    .line 59
    :try_start_9
    sget-object v9, Lmb0/e;->d:Lmb0/e;

    .line 60
    .line 61
    aput v7, v0, v8
    :try_end_9
    .catch Ljava/lang/NoSuchFieldError; {:try_start_9 .. :try_end_9} :catch_9

    .line 62
    .line 63
    :catch_9
    const/16 v8, 0x9

    .line 64
    .line 65
    const/16 v9, 0xa

    .line 66
    .line 67
    :try_start_a
    sget-object v10, Lmb0/e;->d:Lmb0/e;

    .line 68
    .line 69
    aput v8, v0, v9
    :try_end_a
    .catch Ljava/lang/NoSuchFieldError; {:try_start_a .. :try_end_a} :catch_a

    .line 70
    .line 71
    :catch_a
    :try_start_b
    sget-object v10, Lmb0/e;->d:Lmb0/e;

    .line 72
    .line 73
    aput v9, v0, v8
    :try_end_b
    .catch Ljava/lang/NoSuchFieldError; {:try_start_b .. :try_end_b} :catch_b

    .line 74
    .line 75
    :catch_b
    :try_start_c
    sget-object v8, Lmb0/e;->d:Lmb0/e;

    .line 76
    .line 77
    const/16 v8, 0xb

    .line 78
    .line 79
    aput v8, v0, v7
    :try_end_c
    .catch Ljava/lang/NoSuchFieldError; {:try_start_c .. :try_end_c} :catch_c

    .line 80
    .line 81
    :catch_c
    invoke-static {}, Lcn0/a;->values()[Lcn0/a;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    array-length v0, v0

    .line 86
    new-array v0, v0, [I

    .line 87
    .line 88
    :try_start_d
    aput v2, v0, v3
    :try_end_d
    .catch Ljava/lang/NoSuchFieldError; {:try_start_d .. :try_end_d} :catch_d

    .line 89
    .line 90
    :catch_d
    :try_start_e
    sget-object v7, Lcn0/a;->d:Lcn0/a;

    .line 91
    .line 92
    aput v3, v0, v5
    :try_end_e
    .catch Ljava/lang/NoSuchFieldError; {:try_start_e .. :try_end_e} :catch_e

    .line 93
    .line 94
    :catch_e
    :try_start_f
    sget-object v3, Lcn0/a;->d:Lcn0/a;

    .line 95
    .line 96
    aput v5, v0, v1
    :try_end_f
    .catch Ljava/lang/NoSuchFieldError; {:try_start_f .. :try_end_f} :catch_f

    .line 97
    .line 98
    :catch_f
    :try_start_10
    sget-object v1, Lcn0/a;->d:Lcn0/a;

    .line 99
    .line 100
    aput v4, v0, v2
    :try_end_10
    .catch Ljava/lang/NoSuchFieldError; {:try_start_10 .. :try_end_10} :catch_10

    .line 101
    .line 102
    :catch_10
    :try_start_11
    sget-object v1, Lcn0/a;->d:Lcn0/a;

    .line 103
    .line 104
    aput v6, v0, v4
    :try_end_11
    .catch Ljava/lang/NoSuchFieldError; {:try_start_11 .. :try_end_11} :catch_11

    .line 105
    .line 106
    :catch_11
    return-void
.end method
