.class public abstract Ldx0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldx0/d;


# static fields
.field public static final synthetic h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;


# instance fields
.field public final d:I

.field public final e:I

.field public final f:Ljava/util/concurrent/atomic/AtomicReferenceArray;

.field public final g:[I

.field private volatile synthetic top:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Ldx0/c;

    .line 2
    .line 3
    const-string v1, "top"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Ldx0/c;->h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-lez p1, :cond_1

    .line 5
    .line 6
    const v0, 0x1fffffff

    .line 7
    .line 8
    .line 9
    if-gt p1, v0, :cond_0

    .line 10
    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    iput-wide v0, p0, Ldx0/c;->top:J

    .line 14
    .line 15
    mul-int/lit8 p1, p1, 0x4

    .line 16
    .line 17
    add-int/lit8 p1, p1, -0x1

    .line 18
    .line 19
    invoke-static {p1}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    mul-int/lit8 p1, p1, 0x2

    .line 24
    .line 25
    iput p1, p0, Ldx0/c;->d:I

    .line 26
    .line 27
    invoke-static {p1}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    add-int/lit8 v0, v0, 0x1

    .line 32
    .line 33
    iput v0, p0, Ldx0/c;->e:I

    .line 34
    .line 35
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 36
    .line 37
    add-int/lit8 p1, p1, 0x1

    .line 38
    .line 39
    invoke-direct {v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;-><init>(I)V

    .line 40
    .line 41
    .line 42
    iput-object v0, p0, Ldx0/c;->f:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 43
    .line 44
    new-array p1, p1, [I

    .line 45
    .line 46
    iput-object p1, p0, Ldx0/c;->g:[I

    .line 47
    .line 48
    return-void

    .line 49
    :cond_0
    const-string p0, "capacity should be less or equal to 536870911 but it is "

    .line 50
    .line 51
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1

    .line 65
    :cond_1
    const-string p0, "capacity should be positive but it is "

    .line 66
    .line 67
    invoke-static {p1, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p1
.end method


# virtual methods
.method public final X()Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ldx0/c;->d()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ldx0/c;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-virtual {p0}, Ldx0/c;->b()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    return-object p1
.end method

.method public abstract b()Ljava/lang/Object;
.end method

.method public final d()Ljava/lang/Object;
    .locals 10

    .line 1
    :goto_0
    iget-wide v2, p0, Ldx0/c;->top:J

    .line 2
    .line 3
    const-wide/16 v0, 0x0

    .line 4
    .line 5
    cmp-long v0, v2, v0

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    :goto_1
    move v6, v1

    .line 11
    move-object v1, p0

    .line 12
    goto :goto_2

    .line 13
    :cond_0
    const/16 v0, 0x20

    .line 14
    .line 15
    shr-long v4, v2, v0

    .line 16
    .line 17
    const-wide v6, 0xffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    and-long/2addr v4, v6

    .line 23
    const-wide/16 v8, 0x1

    .line 24
    .line 25
    add-long/2addr v4, v8

    .line 26
    and-long/2addr v6, v2

    .line 27
    long-to-int v6, v6

    .line 28
    if-nez v6, :cond_1

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    iget-object v1, p0, Ldx0/c;->g:[I

    .line 32
    .line 33
    aget v1, v1, v6

    .line 34
    .line 35
    shl-long/2addr v4, v0

    .line 36
    int-to-long v0, v1

    .line 37
    or-long/2addr v4, v0

    .line 38
    sget-object v0, Ldx0/c;->h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 39
    .line 40
    move-object v1, p0

    .line 41
    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-eqz p0, :cond_3

    .line 46
    .line 47
    :goto_2
    const/4 p0, 0x0

    .line 48
    if-nez v6, :cond_2

    .line 49
    .line 50
    return-object p0

    .line 51
    :cond_2
    iget-object v0, v1, Ldx0/c;->f:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 52
    .line 53
    invoke-virtual {v0, v6, p0}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->getAndSet(ILjava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :cond_3
    move-object p0, v1

    .line 59
    goto :goto_0
.end method

.method public final dispose()V
    .locals 1

    .line 1
    :cond_0
    invoke-virtual {p0}, Ldx0/c;->d()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void
.end method

.method public final o0(Ljava/lang/Object;)V
    .locals 10

    .line 1
    const-string v0, "instance"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "instance"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const v1, -0x61c88647

    .line 16
    .line 17
    .line 18
    mul-int/2addr v0, v1

    .line 19
    iget v1, p0, Ldx0/c;->e:I

    .line 20
    .line 21
    ushr-int/2addr v0, v1

    .line 22
    add-int/lit8 v0, v0, 0x1

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    :goto_0
    const/16 v2, 0x8

    .line 26
    .line 27
    if-ge v1, v2, :cond_5

    .line 28
    .line 29
    iget-object v2, p0, Ldx0/c;->f:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 30
    .line 31
    :goto_1
    const/4 v3, 0x0

    .line 32
    invoke-virtual {v2, v0, v3, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->compareAndSet(ILjava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    if-eqz v3, :cond_2

    .line 37
    .line 38
    if-lez v0, :cond_1

    .line 39
    .line 40
    :goto_2
    iget-wide v6, p0, Ldx0/c;->top:J

    .line 41
    .line 42
    const/16 p1, 0x20

    .line 43
    .line 44
    shr-long v1, v6, p1

    .line 45
    .line 46
    const-wide v3, 0xffffffffL

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    and-long/2addr v1, v3

    .line 52
    const-wide/16 v8, 0x1

    .line 53
    .line 54
    add-long/2addr v1, v8

    .line 55
    and-long/2addr v3, v6

    .line 56
    long-to-int v3, v3

    .line 57
    shl-long/2addr v1, p1

    .line 58
    int-to-long v4, v0

    .line 59
    or-long v8, v1, v4

    .line 60
    .line 61
    iget-object p1, p0, Ldx0/c;->g:[I

    .line 62
    .line 63
    aput v3, p1, v0

    .line 64
    .line 65
    sget-object v4, Ldx0/c;->h:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 66
    .line 67
    move-object v5, p0

    .line 68
    invoke-virtual/range {v4 .. v9}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    if-eqz p0, :cond_0

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_0
    move-object p0, v5

    .line 76
    goto :goto_2

    .line 77
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 78
    .line 79
    const-string p1, "index should be positive"

    .line 80
    .line 81
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_2
    move-object v5, p0

    .line 86
    invoke-virtual {v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    if-eqz p0, :cond_4

    .line 91
    .line 92
    add-int/lit8 v0, v0, -0x1

    .line 93
    .line 94
    if-nez v0, :cond_3

    .line 95
    .line 96
    iget p0, v5, Ldx0/c;->d:I

    .line 97
    .line 98
    move v0, p0

    .line 99
    :cond_3
    add-int/lit8 v1, v1, 0x1

    .line 100
    .line 101
    move-object p0, v5

    .line 102
    goto :goto_0

    .line 103
    :cond_4
    move-object p0, v5

    .line 104
    goto :goto_1

    .line 105
    :cond_5
    :goto_3
    return-void
.end method
