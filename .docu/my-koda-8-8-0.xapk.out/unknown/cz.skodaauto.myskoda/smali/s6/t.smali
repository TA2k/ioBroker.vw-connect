.class public final Ls6/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Ljava/lang/ThreadLocal;


# instance fields
.field public final a:I

.field public final b:Lcom/google/firebase/messaging/w;

.field public volatile c:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ls6/t;->d:Ljava/lang/ThreadLocal;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lcom/google/firebase/messaging/w;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Ls6/t;->c:I

    .line 6
    .line 7
    iput-object p1, p0, Ls6/t;->b:Lcom/google/firebase/messaging/w;

    .line 8
    .line 9
    iput p2, p0, Ls6/t;->a:I

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(I)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Ls6/t;->b()Lt6/a;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/16 v0, 0x10

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ld6/h0;->a(I)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iget-object v1, p0, Ld6/h0;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Ljava/nio/ByteBuffer;

    .line 16
    .line 17
    iget p0, p0, Ld6/h0;->d:I

    .line 18
    .line 19
    add-int/2addr v0, p0

    .line 20
    invoke-virtual {v1, v0}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v0

    .line 25
    add-int/lit8 p0, p0, 0x4

    .line 26
    .line 27
    mul-int/lit8 p1, p1, 0x4

    .line 28
    .line 29
    add-int/2addr p1, p0

    .line 30
    invoke-virtual {v1, p1}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    return p0

    .line 35
    :cond_0
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public final b()Lt6/a;
    .locals 4

    .line 1
    sget-object v0, Ls6/t;->d:Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lt6/a;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    new-instance v1, Lt6/a;

    .line 12
    .line 13
    invoke-direct {v1}, Ld6/h0;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    :cond_0
    iget-object v0, p0, Ls6/t;->b:Lcom/google/firebase/messaging/w;

    .line 20
    .line 21
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lt6/b;

    .line 24
    .line 25
    const/4 v2, 0x6

    .line 26
    invoke-virtual {v0, v2}, Ld6/h0;->a(I)I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_2

    .line 31
    .line 32
    iget v3, v0, Ld6/h0;->d:I

    .line 33
    .line 34
    add-int/2addr v2, v3

    .line 35
    iget-object v3, v0, Ld6/h0;->g:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v3, Ljava/nio/ByteBuffer;

    .line 38
    .line 39
    invoke-virtual {v3, v2}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    add-int/2addr v3, v2

    .line 44
    add-int/lit8 v3, v3, 0x4

    .line 45
    .line 46
    iget p0, p0, Ls6/t;->a:I

    .line 47
    .line 48
    mul-int/lit8 p0, p0, 0x4

    .line 49
    .line 50
    add-int/2addr p0, v3

    .line 51
    iget-object v2, v0, Ld6/h0;->g:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v2, Ljava/nio/ByteBuffer;

    .line 54
    .line 55
    invoke-virtual {v2, p0}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    add-int/2addr v2, p0

    .line 60
    iget-object p0, v0, Ld6/h0;->g:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p0, Ljava/nio/ByteBuffer;

    .line 63
    .line 64
    iput-object p0, v1, Ld6/h0;->g:Ljava/lang/Object;

    .line 65
    .line 66
    if-eqz p0, :cond_1

    .line 67
    .line 68
    iput v2, v1, Ld6/h0;->d:I

    .line 69
    .line 70
    invoke-virtual {p0, v2}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    sub-int/2addr v2, p0

    .line 75
    iput v2, v1, Ld6/h0;->e:I

    .line 76
    .line 77
    iget-object p0, v1, Ld6/h0;->g:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Ljava/nio/ByteBuffer;

    .line 80
    .line 81
    invoke-virtual {p0, v2}, Ljava/nio/ByteBuffer;->getShort(I)S

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    iput p0, v1, Ld6/h0;->f:I

    .line 86
    .line 87
    return-object v1

    .line 88
    :cond_1
    const/4 p0, 0x0

    .line 89
    iput p0, v1, Ld6/h0;->d:I

    .line 90
    .line 91
    iput p0, v1, Ld6/h0;->e:I

    .line 92
    .line 93
    iput p0, v1, Ld6/h0;->f:I

    .line 94
    .line 95
    :cond_2
    return-object v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", id:"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0}, Ls6/t;->b()Lt6/a;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    const/4 v2, 0x4

    .line 23
    invoke-virtual {v1, v2}, Ld6/h0;->a(I)I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const/4 v3, 0x0

    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    iget-object v4, v1, Ld6/h0;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v4, Ljava/nio/ByteBuffer;

    .line 33
    .line 34
    iget v1, v1, Ld6/h0;->d:I

    .line 35
    .line 36
    add-int/2addr v2, v1

    .line 37
    invoke-virtual {v4, v2}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    move v1, v3

    .line 43
    :goto_0
    invoke-static {v1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v1, ", codepoints:"

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Ls6/t;->b()Lt6/a;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    const/16 v2, 0x10

    .line 60
    .line 61
    invoke-virtual {v1, v2}, Ld6/h0;->a(I)I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-eqz v2, :cond_1

    .line 66
    .line 67
    iget v4, v1, Ld6/h0;->d:I

    .line 68
    .line 69
    add-int/2addr v2, v4

    .line 70
    iget-object v4, v1, Ld6/h0;->g:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v4, Ljava/nio/ByteBuffer;

    .line 73
    .line 74
    invoke-virtual {v4, v2}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    add-int/2addr v4, v2

    .line 79
    iget-object v1, v1, Ld6/h0;->g:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v1, Ljava/nio/ByteBuffer;

    .line 82
    .line 83
    invoke-virtual {v1, v4}, Ljava/nio/ByteBuffer;->getInt(I)I

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    goto :goto_1

    .line 88
    :cond_1
    move v1, v3

    .line 89
    :goto_1
    if-ge v3, v1, :cond_2

    .line 90
    .line 91
    invoke-virtual {p0, v3}, Ls6/t;->a(I)I

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    invoke-static {v2}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    const-string v2, " "

    .line 103
    .line 104
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    add-int/lit8 v3, v3, 0x1

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_2
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0
.end method
