.class public Laz0/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field private volatile synthetic _size$volatile:I

.field public a:[Lvy0/w0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Laz0/v;

    .line 2
    .line 3
    const-string v1, "_size$volatile"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Laz0/v;->b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Lvy0/w0;)V
    .locals 4

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lvy0/x0;

    .line 3
    .line 4
    invoke-virtual {p1, v0}, Lvy0/w0;->c(Lvy0/x0;)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Laz0/v;->a:[Lvy0/w0;

    .line 8
    .line 9
    sget-object v1, Laz0/v;->b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    const/4 v0, 0x4

    .line 14
    new-array v0, v0, [Lvy0/w0;

    .line 15
    .line 16
    iput-object v0, p0, Laz0/v;->a:[Lvy0/w0;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    array-length v3, v0

    .line 24
    if-lt v2, v3, :cond_1

    .line 25
    .line 26
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    mul-int/lit8 v2, v2, 0x2

    .line 31
    .line 32
    invoke-static {v0, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    const-string v2, "copyOf(...)"

    .line 37
    .line 38
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    check-cast v0, [Lvy0/w0;

    .line 42
    .line 43
    iput-object v0, p0, Laz0/v;->a:[Lvy0/w0;

    .line 44
    .line 45
    :cond_1
    :goto_0
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    add-int/lit8 v3, v2, 0x1

    .line 50
    .line 51
    invoke-virtual {v1, p0, v3}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->set(Ljava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    aput-object p1, v0, v2

    .line 55
    .line 56
    iput v2, p1, Lvy0/w0;->e:I

    .line 57
    .line 58
    invoke-virtual {p0, v2}, Laz0/v;->c(I)V

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public final b(I)Lvy0/w0;
    .locals 8

    .line 1
    iget-object v0, p0, Laz0/v;->a:[Lvy0/w0;

    .line 2
    .line 3
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    sget-object v1, Laz0/v;->b:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 7
    .line 8
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    const/4 v3, -0x1

    .line 13
    add-int/2addr v2, v3

    .line 14
    invoke-virtual {v1, p0, v2}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->set(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-ge p1, v2, :cond_4

    .line 22
    .line 23
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    invoke-virtual {p0, p1, v2}, Laz0/v;->d(II)V

    .line 28
    .line 29
    .line 30
    add-int/lit8 v2, p1, -0x1

    .line 31
    .line 32
    div-int/lit8 v2, v2, 0x2

    .line 33
    .line 34
    if-lez p1, :cond_0

    .line 35
    .line 36
    aget-object v4, v0, p1

    .line 37
    .line 38
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    aget-object v5, v0, v2

    .line 42
    .line 43
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v4, v5}, Lvy0/w0;->compareTo(Ljava/lang/Object;)I

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    if-gez v4, :cond_0

    .line 51
    .line 52
    invoke-virtual {p0, p1, v2}, Laz0/v;->d(II)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, v2}, Laz0/v;->c(I)V

    .line 56
    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_0
    :goto_0
    mul-int/lit8 v2, p1, 0x2

    .line 60
    .line 61
    add-int/lit8 v4, v2, 0x1

    .line 62
    .line 63
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    if-lt v4, v5, :cond_1

    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_1
    iget-object v5, p0, Laz0/v;->a:[Lvy0/w0;

    .line 71
    .line 72
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    add-int/lit8 v2, v2, 0x2

    .line 76
    .line 77
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    if-ge v2, v6, :cond_2

    .line 82
    .line 83
    aget-object v6, v5, v2

    .line 84
    .line 85
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    aget-object v7, v5, v4

    .line 89
    .line 90
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v6, v7}, Lvy0/w0;->compareTo(Ljava/lang/Object;)I

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    if-gez v6, :cond_2

    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_2
    move v2, v4

    .line 101
    :goto_1
    aget-object v4, v5, p1

    .line 102
    .line 103
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    aget-object v5, v5, v2

    .line 107
    .line 108
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v4, v5}, Lvy0/w0;->compareTo(Ljava/lang/Object;)I

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    if-gtz v4, :cond_3

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_3
    invoke-virtual {p0, p1, v2}, Laz0/v;->d(II)V

    .line 119
    .line 120
    .line 121
    move p1, v2

    .line 122
    goto :goto_0

    .line 123
    :cond_4
    :goto_2
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    aget-object p1, v0, p1

    .line 128
    .line 129
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    const/4 v2, 0x0

    .line 133
    invoke-virtual {p1, v2}, Lvy0/w0;->c(Lvy0/x0;)V

    .line 134
    .line 135
    .line 136
    iput v3, p1, Lvy0/w0;->e:I

    .line 137
    .line 138
    invoke-virtual {v1, p0}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    .line 139
    .line 140
    .line 141
    move-result p0

    .line 142
    aput-object v2, v0, p0

    .line 143
    .line 144
    return-object p1
.end method

.method public final c(I)V
    .locals 3

    .line 1
    :goto_0
    if-gtz p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    iget-object v0, p0, Laz0/v;->a:[Lvy0/w0;

    .line 5
    .line 6
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    add-int/lit8 v1, p1, -0x1

    .line 10
    .line 11
    div-int/lit8 v1, v1, 0x2

    .line 12
    .line 13
    aget-object v2, v0, v1

    .line 14
    .line 15
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    aget-object v0, v0, p1

    .line 19
    .line 20
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-interface {v2, v0}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-gtz v0, :cond_1

    .line 28
    .line 29
    :goto_1
    return-void

    .line 30
    :cond_1
    invoke-virtual {p0, p1, v1}, Laz0/v;->d(II)V

    .line 31
    .line 32
    .line 33
    move p1, v1

    .line 34
    goto :goto_0
.end method

.method public final d(II)V
    .locals 2

    .line 1
    iget-object p0, p0, Laz0/v;->a:[Lvy0/w0;

    .line 2
    .line 3
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    aget-object v0, p0, p2

    .line 7
    .line 8
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    aget-object v1, p0, p1

    .line 12
    .line 13
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    aput-object v0, p0, p1

    .line 17
    .line 18
    aput-object v1, p0, p2

    .line 19
    .line 20
    iput p1, v0, Lvy0/w0;->e:I

    .line 21
    .line 22
    iput p2, v1, Lvy0/w0;->e:I

    .line 23
    .line 24
    return-void
.end method
