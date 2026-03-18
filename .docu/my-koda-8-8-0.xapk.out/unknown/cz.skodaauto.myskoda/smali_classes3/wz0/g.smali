.class public final Lwz0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[C

.field public static final b:[B


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    const/16 v0, 0x75

    .line 2
    .line 3
    new-array v0, v0, [C

    .line 4
    .line 5
    sput-object v0, Lwz0/g;->a:[C

    .line 6
    .line 7
    const/16 v0, 0x7e

    .line 8
    .line 9
    new-array v0, v0, [B

    .line 10
    .line 11
    sput-object v0, Lwz0/g;->b:[B

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    move v1, v0

    .line 15
    :goto_0
    const/16 v2, 0x20

    .line 16
    .line 17
    if-ge v1, v2, :cond_0

    .line 18
    .line 19
    add-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/16 v1, 0x62

    .line 23
    .line 24
    const/16 v3, 0x8

    .line 25
    .line 26
    invoke-static {v1, v3}, Lwz0/g;->a(CI)V

    .line 27
    .line 28
    .line 29
    const/16 v1, 0x74

    .line 30
    .line 31
    const/16 v4, 0x9

    .line 32
    .line 33
    invoke-static {v1, v4}, Lwz0/g;->a(CI)V

    .line 34
    .line 35
    .line 36
    const/16 v1, 0x6e

    .line 37
    .line 38
    const/16 v5, 0xa

    .line 39
    .line 40
    invoke-static {v1, v5}, Lwz0/g;->a(CI)V

    .line 41
    .line 42
    .line 43
    const/16 v1, 0xc

    .line 44
    .line 45
    const/16 v6, 0x66

    .line 46
    .line 47
    invoke-static {v6, v1}, Lwz0/g;->a(CI)V

    .line 48
    .line 49
    .line 50
    const/16 v1, 0x72

    .line 51
    .line 52
    const/16 v6, 0xd

    .line 53
    .line 54
    invoke-static {v1, v6}, Lwz0/g;->a(CI)V

    .line 55
    .line 56
    .line 57
    const/16 v1, 0x2f

    .line 58
    .line 59
    invoke-static {v1, v1}, Lwz0/g;->a(CI)V

    .line 60
    .line 61
    .line 62
    const/16 v1, 0x22

    .line 63
    .line 64
    invoke-static {v1, v1}, Lwz0/g;->a(CI)V

    .line 65
    .line 66
    .line 67
    const/16 v7, 0x5c

    .line 68
    .line 69
    invoke-static {v7, v7}, Lwz0/g;->a(CI)V

    .line 70
    .line 71
    .line 72
    sget-object v8, Lwz0/g;->b:[B

    .line 73
    .line 74
    :goto_1
    const/16 v9, 0x21

    .line 75
    .line 76
    if-ge v0, v9, :cond_1

    .line 77
    .line 78
    const/16 v9, 0x7f

    .line 79
    .line 80
    aput-byte v9, v8, v0

    .line 81
    .line 82
    add-int/lit8 v0, v0, 0x1

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_1
    const/4 v0, 0x3

    .line 86
    aput-byte v0, v8, v4

    .line 87
    .line 88
    aput-byte v0, v8, v5

    .line 89
    .line 90
    aput-byte v0, v8, v6

    .line 91
    .line 92
    aput-byte v0, v8, v2

    .line 93
    .line 94
    const/16 v0, 0x2c

    .line 95
    .line 96
    const/4 v2, 0x4

    .line 97
    aput-byte v2, v8, v0

    .line 98
    .line 99
    const/16 v0, 0x3a

    .line 100
    .line 101
    const/4 v2, 0x5

    .line 102
    aput-byte v2, v8, v0

    .line 103
    .line 104
    const/16 v0, 0x7b

    .line 105
    .line 106
    const/4 v2, 0x6

    .line 107
    aput-byte v2, v8, v0

    .line 108
    .line 109
    const/16 v0, 0x7d

    .line 110
    .line 111
    const/4 v2, 0x7

    .line 112
    aput-byte v2, v8, v0

    .line 113
    .line 114
    const/16 v0, 0x5b

    .line 115
    .line 116
    aput-byte v3, v8, v0

    .line 117
    .line 118
    const/16 v0, 0x5d

    .line 119
    .line 120
    aput-byte v4, v8, v0

    .line 121
    .line 122
    const/4 v0, 0x1

    .line 123
    aput-byte v0, v8, v1

    .line 124
    .line 125
    const/4 v0, 0x2

    .line 126
    aput-byte v0, v8, v7

    .line 127
    .line 128
    return-void
.end method

.method public static a(CI)V
    .locals 1

    .line 1
    const/16 v0, 0x75

    .line 2
    .line 3
    if-eq p0, v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lwz0/g;->a:[C

    .line 6
    .line 7
    int-to-char p1, p1

    .line 8
    aput-char p1, v0, p0

    .line 9
    .line 10
    :cond_0
    return-void
.end method
