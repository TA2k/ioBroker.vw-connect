.class public final Lcom/google/crypto/tink/shaded/protobuf/r0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/crypto/tink/shaded/protobuf/a1;


# static fields
.field public static final o:[I

.field public static final p:Lsun/misc/Unsafe;


# instance fields
.field public final a:[I

.field public final b:[Ljava/lang/Object;

.field public final c:I

.field public final d:I

.field public final e:Lcom/google/crypto/tink/shaded/protobuf/a;

.field public final f:Z

.field public final g:Z

.field public final h:[I

.field public final i:I

.field public final j:I

.field public final k:Lcom/google/crypto/tink/shaded/protobuf/t0;

.field public final l:Lcom/google/crypto/tink/shaded/protobuf/j0;

.field public final m:Lcom/google/crypto/tink/shaded/protobuf/d1;

.field public final n:Lcom/google/crypto/tink/shaded/protobuf/n0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->o:[I

    .line 5
    .line 6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/l1;->i()Lsun/misc/Unsafe;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>([I[Ljava/lang/Object;IILcom/google/crypto/tink/shaded/protobuf/a;Z[IIILcom/google/crypto/tink/shaded/protobuf/t0;Lcom/google/crypto/tink/shaded/protobuf/j0;Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->b:[Ljava/lang/Object;

    .line 7
    .line 8
    iput p3, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->c:I

    .line 9
    .line 10
    iput p4, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->d:I

    .line 11
    .line 12
    instance-of p1, p5, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 13
    .line 14
    iput-boolean p1, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->f:Z

    .line 15
    .line 16
    iput-boolean p6, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->g:Z

    .line 17
    .line 18
    iput-object p7, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->h:[I

    .line 19
    .line 20
    iput p8, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->i:I

    .line 21
    .line 22
    iput p9, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->j:I

    .line 23
    .line 24
    iput-object p10, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->k:Lcom/google/crypto/tink/shaded/protobuf/t0;

    .line 25
    .line 26
    iput-object p11, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->l:Lcom/google/crypto/tink/shaded/protobuf/j0;

    .line 27
    .line 28
    iput-object p12, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 29
    .line 30
    iput-object p5, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->e:Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 31
    .line 32
    iput-object p14, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 33
    .line 34
    return-void
.end method

.method public static A(JLjava/lang/Object;)I
    .locals 1

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public static B(JLjava/lang/Object;)J
    .locals 1

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Long;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    return-wide p0
.end method

.method public static J(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;
    .locals 5

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NoSuchFieldException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    invoke-virtual {p0}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    array-length v1, v0

    .line 11
    const/4 v2, 0x0

    .line 12
    :goto_0
    if-ge v2, v1, :cond_1

    .line 13
    .line 14
    aget-object v3, v0, v2

    .line 15
    .line 16
    invoke-virtual {v3}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    invoke-virtual {p1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    if-eqz v4, :cond_0

    .line 25
    .line 26
    return-object v3

    .line 27
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    new-instance v1, Ljava/lang/RuntimeException;

    .line 31
    .line 32
    const-string v2, "Field "

    .line 33
    .line 34
    const-string v3, " for "

    .line 35
    .line 36
    invoke-static {v2, p1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string p0, " not found. Known fields are "

    .line 48
    .line 49
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-static {v0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-direct {v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v1
.end method

.method public static N(I)I
    .locals 1

    .line 1
    const/high16 v0, 0xff00000

    .line 2
    .line 3
    and-int/2addr p0, v0

    .line 4
    ushr-int/lit8 p0, p0, 0x14

    .line 5
    .line 6
    return p0
.end method

.method public static Q(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V
    .locals 5

    .line 1
    instance-of v0, p1, Ljava/lang/String;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    check-cast p1, Ljava/lang/String;

    .line 6
    .line 7
    iget-object p2, p2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p2, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 10
    .line 11
    const/4 v0, 0x2

    .line 12
    invoke-virtual {p2, p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 13
    .line 14
    .line 15
    iget p0, p2, Lcom/google/crypto/tink/shaded/protobuf/k;->c:I

    .line 16
    .line 17
    iget-object v0, p2, Lcom/google/crypto/tink/shaded/protobuf/k;->b:[B

    .line 18
    .line 19
    iget v1, p2, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 20
    .line 21
    :try_start_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    mul-int/lit8 v2, v2, 0x3

    .line 26
    .line 27
    invoke-static {v2}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-ne v3, v2, :cond_0

    .line 40
    .line 41
    add-int v2, v1, v3

    .line 42
    .line 43
    iput v2, p2, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 44
    .line 45
    sub-int/2addr p0, v2

    .line 46
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/o1;->a:Lcom/google/crypto/tink/shaded/protobuf/q0;

    .line 47
    .line 48
    invoke-virtual {v4, v2, p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/q0;->s(IILjava/lang/String;[B)I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    iput v1, p2, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 53
    .line 54
    sub-int v0, p0, v1

    .line 55
    .line 56
    sub-int/2addr v0, v3

    .line 57
    invoke-virtual {p2, v0}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 58
    .line 59
    .line 60
    iput p0, p2, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 61
    .line 62
    return-void

    .line 63
    :catch_0
    move-exception p0

    .line 64
    goto :goto_0

    .line 65
    :cond_0
    invoke-static {p1}, Lcom/google/crypto/tink/shaded/protobuf/o1;->b(Ljava/lang/String;)I

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    invoke-virtual {p2, v2}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 70
    .line 71
    .line 72
    iget v2, p2, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 73
    .line 74
    sub-int/2addr p0, v2

    .line 75
    sget-object v3, Lcom/google/crypto/tink/shaded/protobuf/o1;->a:Lcom/google/crypto/tink/shaded/protobuf/q0;

    .line 76
    .line 77
    invoke-virtual {v3, v2, p0, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/q0;->s(IILjava/lang/String;[B)I

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    iput p0, p2, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I
    :try_end_0
    .catch Lcom/google/crypto/tink/shaded/protobuf/n1; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_1

    .line 82
    .line 83
    return-void

    .line 84
    :catch_1
    move-exception p0

    .line 85
    new-instance p1, Lcom/google/crypto/tink/shaded/protobuf/l;

    .line 86
    .line 87
    invoke-direct {p1, p0}, Lcom/google/crypto/tink/shaded/protobuf/l;-><init>(Ljava/lang/IndexOutOfBoundsException;)V

    .line 88
    .line 89
    .line 90
    throw p1

    .line 91
    :goto_0
    iput v1, p2, Lcom/google/crypto/tink/shaded/protobuf/k;->d:I

    .line 92
    .line 93
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/k;->e:Ljava/util/logging/Logger;

    .line 94
    .line 95
    sget-object v1, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 96
    .line 97
    const-string v2, "Converting ill-formed UTF-16. Your Protocol Buffer will not round trip correctly!"

    .line 98
    .line 99
    invoke-virtual {v0, v1, v2, p0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 100
    .line 101
    .line 102
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 103
    .line 104
    invoke-virtual {p1, p0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    :try_start_1
    array-length p1, p0

    .line 109
    invoke-virtual {p2, p1}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 110
    .line 111
    .line 112
    array-length p1, p0

    .line 113
    const/4 v0, 0x0

    .line 114
    invoke-virtual {p2, p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/k;->K([BII)V
    :try_end_1
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_1 .. :try_end_1} :catch_3
    .catch Lcom/google/crypto/tink/shaded/protobuf/l; {:try_start_1 .. :try_end_1} :catch_2

    .line 115
    .line 116
    .line 117
    return-void

    .line 118
    :catch_2
    move-exception p0

    .line 119
    throw p0

    .line 120
    :catch_3
    move-exception p0

    .line 121
    new-instance p1, Lcom/google/crypto/tink/shaded/protobuf/l;

    .line 122
    .line 123
    invoke-direct {p1, p0}, Lcom/google/crypto/tink/shaded/protobuf/l;-><init>(Ljava/lang/IndexOutOfBoundsException;)V

    .line 124
    .line 125
    .line 126
    throw p1

    .line 127
    :cond_1
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 128
    .line 129
    invoke-virtual {p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/m;->a(ILcom/google/crypto/tink/shaded/protobuf/i;)V

    .line 130
    .line 131
    .line 132
    return-void
.end method

.method public static t(JLjava/lang/Object;)Ljava/util/List;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 2
    .line 3
    invoke-virtual {v0, p2, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/util/List;

    .line 8
    .line 9
    return-object p0
.end method

.method public static x(Lcom/google/crypto/tink/shaded/protobuf/z0;Lcom/google/crypto/tink/shaded/protobuf/t0;Lcom/google/crypto/tink/shaded/protobuf/j0;Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/n0;)Lcom/google/crypto/tink/shaded/protobuf/r0;
    .locals 1

    .line 1
    instance-of v0, p0, Lcom/google/crypto/tink/shaded/protobuf/z0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static/range {p0 .. p5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->y(Lcom/google/crypto/tink/shaded/protobuf/z0;Lcom/google/crypto/tink/shaded/protobuf/t0;Lcom/google/crypto/tink/shaded/protobuf/j0;Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/n0;)Lcom/google/crypto/tink/shaded/protobuf/r0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    new-instance p0, Ljava/lang/ClassCastException;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0
.end method

.method public static y(Lcom/google/crypto/tink/shaded/protobuf/z0;Lcom/google/crypto/tink/shaded/protobuf/t0;Lcom/google/crypto/tink/shaded/protobuf/j0;Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/n0;)Lcom/google/crypto/tink/shaded/protobuf/r0;
    .locals 37

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lcom/google/crypto/tink/shaded/protobuf/z0;->d:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    and-int/2addr v1, v2

    .line 7
    const/4 v3, 0x0

    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    move v10, v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move v10, v2

    .line 13
    :goto_0
    iget-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/z0;->b:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    const v7, 0xd800

    .line 24
    .line 25
    .line 26
    if-lt v5, v7, :cond_2

    .line 27
    .line 28
    and-int/lit16 v5, v5, 0x1fff

    .line 29
    .line 30
    move v8, v2

    .line 31
    const/16 v9, 0xd

    .line 32
    .line 33
    :goto_1
    add-int/lit8 v11, v8, 0x1

    .line 34
    .line 35
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 36
    .line 37
    .line 38
    move-result v8

    .line 39
    if-lt v8, v7, :cond_1

    .line 40
    .line 41
    and-int/lit16 v8, v8, 0x1fff

    .line 42
    .line 43
    shl-int/2addr v8, v9

    .line 44
    or-int/2addr v5, v8

    .line 45
    add-int/lit8 v9, v9, 0xd

    .line 46
    .line 47
    move v8, v11

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    shl-int/2addr v8, v9

    .line 50
    or-int/2addr v5, v8

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    move v11, v2

    .line 53
    :goto_2
    add-int/lit8 v8, v11, 0x1

    .line 54
    .line 55
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 56
    .line 57
    .line 58
    move-result v9

    .line 59
    if-lt v9, v7, :cond_4

    .line 60
    .line 61
    and-int/lit16 v9, v9, 0x1fff

    .line 62
    .line 63
    const/16 v11, 0xd

    .line 64
    .line 65
    :goto_3
    add-int/lit8 v12, v8, 0x1

    .line 66
    .line 67
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 68
    .line 69
    .line 70
    move-result v8

    .line 71
    if-lt v8, v7, :cond_3

    .line 72
    .line 73
    and-int/lit16 v8, v8, 0x1fff

    .line 74
    .line 75
    shl-int/2addr v8, v11

    .line 76
    or-int/2addr v9, v8

    .line 77
    add-int/lit8 v11, v11, 0xd

    .line 78
    .line 79
    move v8, v12

    .line 80
    goto :goto_3

    .line 81
    :cond_3
    shl-int/2addr v8, v11

    .line 82
    or-int/2addr v9, v8

    .line 83
    move v8, v12

    .line 84
    :cond_4
    if-nez v9, :cond_5

    .line 85
    .line 86
    sget-object v9, Lcom/google/crypto/tink/shaded/protobuf/r0;->o:[I

    .line 87
    .line 88
    move v6, v3

    .line 89
    move v12, v6

    .line 90
    move v13, v12

    .line 91
    move v14, v13

    .line 92
    move v15, v14

    .line 93
    move-object v11, v9

    .line 94
    move v9, v15

    .line 95
    goto/16 :goto_d

    .line 96
    .line 97
    :cond_5
    add-int/lit8 v9, v8, 0x1

    .line 98
    .line 99
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 100
    .line 101
    .line 102
    move-result v8

    .line 103
    if-lt v8, v7, :cond_7

    .line 104
    .line 105
    and-int/lit16 v8, v8, 0x1fff

    .line 106
    .line 107
    const/16 v11, 0xd

    .line 108
    .line 109
    :goto_4
    add-int/lit8 v12, v9, 0x1

    .line 110
    .line 111
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 112
    .line 113
    .line 114
    move-result v9

    .line 115
    if-lt v9, v7, :cond_6

    .line 116
    .line 117
    and-int/lit16 v9, v9, 0x1fff

    .line 118
    .line 119
    shl-int/2addr v9, v11

    .line 120
    or-int/2addr v8, v9

    .line 121
    add-int/lit8 v11, v11, 0xd

    .line 122
    .line 123
    move v9, v12

    .line 124
    goto :goto_4

    .line 125
    :cond_6
    shl-int/2addr v9, v11

    .line 126
    or-int/2addr v8, v9

    .line 127
    move v9, v12

    .line 128
    :cond_7
    add-int/lit8 v11, v9, 0x1

    .line 129
    .line 130
    invoke-virtual {v1, v9}, Ljava/lang/String;->charAt(I)C

    .line 131
    .line 132
    .line 133
    move-result v9

    .line 134
    if-lt v9, v7, :cond_9

    .line 135
    .line 136
    and-int/lit16 v9, v9, 0x1fff

    .line 137
    .line 138
    const/16 v12, 0xd

    .line 139
    .line 140
    :goto_5
    add-int/lit8 v13, v11, 0x1

    .line 141
    .line 142
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 143
    .line 144
    .line 145
    move-result v11

    .line 146
    if-lt v11, v7, :cond_8

    .line 147
    .line 148
    and-int/lit16 v11, v11, 0x1fff

    .line 149
    .line 150
    shl-int/2addr v11, v12

    .line 151
    or-int/2addr v9, v11

    .line 152
    add-int/lit8 v12, v12, 0xd

    .line 153
    .line 154
    move v11, v13

    .line 155
    goto :goto_5

    .line 156
    :cond_8
    shl-int/2addr v11, v12

    .line 157
    or-int/2addr v9, v11

    .line 158
    move v11, v13

    .line 159
    :cond_9
    add-int/lit8 v12, v11, 0x1

    .line 160
    .line 161
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 162
    .line 163
    .line 164
    move-result v11

    .line 165
    if-lt v11, v7, :cond_b

    .line 166
    .line 167
    and-int/lit16 v11, v11, 0x1fff

    .line 168
    .line 169
    const/16 v13, 0xd

    .line 170
    .line 171
    :goto_6
    add-int/lit8 v14, v12, 0x1

    .line 172
    .line 173
    invoke-virtual {v1, v12}, Ljava/lang/String;->charAt(I)C

    .line 174
    .line 175
    .line 176
    move-result v12

    .line 177
    if-lt v12, v7, :cond_a

    .line 178
    .line 179
    and-int/lit16 v12, v12, 0x1fff

    .line 180
    .line 181
    shl-int/2addr v12, v13

    .line 182
    or-int/2addr v11, v12

    .line 183
    add-int/lit8 v13, v13, 0xd

    .line 184
    .line 185
    move v12, v14

    .line 186
    goto :goto_6

    .line 187
    :cond_a
    shl-int/2addr v12, v13

    .line 188
    or-int/2addr v11, v12

    .line 189
    move v12, v14

    .line 190
    :cond_b
    add-int/lit8 v13, v12, 0x1

    .line 191
    .line 192
    invoke-virtual {v1, v12}, Ljava/lang/String;->charAt(I)C

    .line 193
    .line 194
    .line 195
    move-result v12

    .line 196
    if-lt v12, v7, :cond_d

    .line 197
    .line 198
    and-int/lit16 v12, v12, 0x1fff

    .line 199
    .line 200
    const/16 v14, 0xd

    .line 201
    .line 202
    :goto_7
    add-int/lit8 v15, v13, 0x1

    .line 203
    .line 204
    invoke-virtual {v1, v13}, Ljava/lang/String;->charAt(I)C

    .line 205
    .line 206
    .line 207
    move-result v13

    .line 208
    if-lt v13, v7, :cond_c

    .line 209
    .line 210
    and-int/lit16 v13, v13, 0x1fff

    .line 211
    .line 212
    shl-int/2addr v13, v14

    .line 213
    or-int/2addr v12, v13

    .line 214
    add-int/lit8 v14, v14, 0xd

    .line 215
    .line 216
    move v13, v15

    .line 217
    goto :goto_7

    .line 218
    :cond_c
    shl-int/2addr v13, v14

    .line 219
    or-int/2addr v12, v13

    .line 220
    move v13, v15

    .line 221
    :cond_d
    add-int/lit8 v14, v13, 0x1

    .line 222
    .line 223
    invoke-virtual {v1, v13}, Ljava/lang/String;->charAt(I)C

    .line 224
    .line 225
    .line 226
    move-result v13

    .line 227
    if-lt v13, v7, :cond_f

    .line 228
    .line 229
    and-int/lit16 v13, v13, 0x1fff

    .line 230
    .line 231
    const/16 v15, 0xd

    .line 232
    .line 233
    :goto_8
    add-int/lit8 v16, v14, 0x1

    .line 234
    .line 235
    invoke-virtual {v1, v14}, Ljava/lang/String;->charAt(I)C

    .line 236
    .line 237
    .line 238
    move-result v14

    .line 239
    if-lt v14, v7, :cond_e

    .line 240
    .line 241
    and-int/lit16 v14, v14, 0x1fff

    .line 242
    .line 243
    shl-int/2addr v14, v15

    .line 244
    or-int/2addr v13, v14

    .line 245
    add-int/lit8 v15, v15, 0xd

    .line 246
    .line 247
    move/from16 v14, v16

    .line 248
    .line 249
    goto :goto_8

    .line 250
    :cond_e
    shl-int/2addr v14, v15

    .line 251
    or-int/2addr v13, v14

    .line 252
    move/from16 v14, v16

    .line 253
    .line 254
    :cond_f
    add-int/lit8 v15, v14, 0x1

    .line 255
    .line 256
    invoke-virtual {v1, v14}, Ljava/lang/String;->charAt(I)C

    .line 257
    .line 258
    .line 259
    move-result v14

    .line 260
    if-lt v14, v7, :cond_11

    .line 261
    .line 262
    and-int/lit16 v14, v14, 0x1fff

    .line 263
    .line 264
    const/16 v16, 0xd

    .line 265
    .line 266
    :goto_9
    add-int/lit8 v17, v15, 0x1

    .line 267
    .line 268
    invoke-virtual {v1, v15}, Ljava/lang/String;->charAt(I)C

    .line 269
    .line 270
    .line 271
    move-result v15

    .line 272
    if-lt v15, v7, :cond_10

    .line 273
    .line 274
    and-int/lit16 v15, v15, 0x1fff

    .line 275
    .line 276
    shl-int v15, v15, v16

    .line 277
    .line 278
    or-int/2addr v14, v15

    .line 279
    add-int/lit8 v16, v16, 0xd

    .line 280
    .line 281
    move/from16 v15, v17

    .line 282
    .line 283
    goto :goto_9

    .line 284
    :cond_10
    shl-int v15, v15, v16

    .line 285
    .line 286
    or-int/2addr v14, v15

    .line 287
    move/from16 v15, v17

    .line 288
    .line 289
    :cond_11
    add-int/lit8 v16, v15, 0x1

    .line 290
    .line 291
    invoke-virtual {v1, v15}, Ljava/lang/String;->charAt(I)C

    .line 292
    .line 293
    .line 294
    move-result v15

    .line 295
    if-lt v15, v7, :cond_13

    .line 296
    .line 297
    and-int/lit16 v15, v15, 0x1fff

    .line 298
    .line 299
    move/from16 v3, v16

    .line 300
    .line 301
    const/16 v16, 0xd

    .line 302
    .line 303
    :goto_a
    add-int/lit8 v18, v3, 0x1

    .line 304
    .line 305
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 306
    .line 307
    .line 308
    move-result v3

    .line 309
    if-lt v3, v7, :cond_12

    .line 310
    .line 311
    and-int/lit16 v3, v3, 0x1fff

    .line 312
    .line 313
    shl-int v3, v3, v16

    .line 314
    .line 315
    or-int/2addr v15, v3

    .line 316
    add-int/lit8 v16, v16, 0xd

    .line 317
    .line 318
    move/from16 v3, v18

    .line 319
    .line 320
    goto :goto_a

    .line 321
    :cond_12
    shl-int v3, v3, v16

    .line 322
    .line 323
    or-int/2addr v15, v3

    .line 324
    move/from16 v3, v18

    .line 325
    .line 326
    goto :goto_b

    .line 327
    :cond_13
    move/from16 v3, v16

    .line 328
    .line 329
    :goto_b
    add-int/lit8 v16, v3, 0x1

    .line 330
    .line 331
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 332
    .line 333
    .line 334
    move-result v3

    .line 335
    if-lt v3, v7, :cond_15

    .line 336
    .line 337
    and-int/lit16 v3, v3, 0x1fff

    .line 338
    .line 339
    move/from16 v6, v16

    .line 340
    .line 341
    const/16 v16, 0xd

    .line 342
    .line 343
    :goto_c
    add-int/lit8 v19, v6, 0x1

    .line 344
    .line 345
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 346
    .line 347
    .line 348
    move-result v6

    .line 349
    if-lt v6, v7, :cond_14

    .line 350
    .line 351
    and-int/lit16 v6, v6, 0x1fff

    .line 352
    .line 353
    shl-int v6, v6, v16

    .line 354
    .line 355
    or-int/2addr v3, v6

    .line 356
    add-int/lit8 v16, v16, 0xd

    .line 357
    .line 358
    move/from16 v6, v19

    .line 359
    .line 360
    goto :goto_c

    .line 361
    :cond_14
    shl-int v6, v6, v16

    .line 362
    .line 363
    or-int/2addr v3, v6

    .line 364
    move/from16 v16, v19

    .line 365
    .line 366
    :cond_15
    add-int v6, v3, v14

    .line 367
    .line 368
    add-int/2addr v6, v15

    .line 369
    new-array v6, v6, [I

    .line 370
    .line 371
    mul-int/lit8 v15, v8, 0x2

    .line 372
    .line 373
    add-int/2addr v15, v9

    .line 374
    move v9, v11

    .line 375
    move-object v11, v6

    .line 376
    move v6, v9

    .line 377
    move v9, v12

    .line 378
    move v12, v3

    .line 379
    move v3, v8

    .line 380
    move/from16 v8, v16

    .line 381
    .line 382
    :goto_d
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 383
    .line 384
    iget-object v7, v0, Lcom/google/crypto/tink/shaded/protobuf/z0;->c:[Ljava/lang/Object;

    .line 385
    .line 386
    move/from16 v20, v3

    .line 387
    .line 388
    iget-object v3, v0, Lcom/google/crypto/tink/shaded/protobuf/z0;->a:Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 389
    .line 390
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 391
    .line 392
    .line 393
    move-result-object v3

    .line 394
    move/from16 v21, v5

    .line 395
    .line 396
    mul-int/lit8 v5, v13, 0x3

    .line 397
    .line 398
    new-array v5, v5, [I

    .line 399
    .line 400
    move-object/from16 v22, v5

    .line 401
    .line 402
    const/4 v5, 0x2

    .line 403
    mul-int/2addr v13, v5

    .line 404
    new-array v13, v13, [Ljava/lang/Object;

    .line 405
    .line 406
    add-int/2addr v14, v12

    .line 407
    move/from16 v25, v12

    .line 408
    .line 409
    move/from16 v26, v14

    .line 410
    .line 411
    const/4 v5, 0x0

    .line 412
    const/16 v23, 0x0

    .line 413
    .line 414
    :goto_e
    if-ge v8, v4, :cond_34

    .line 415
    .line 416
    add-int/lit8 v27, v8, 0x1

    .line 417
    .line 418
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 419
    .line 420
    .line 421
    move-result v8

    .line 422
    move/from16 v28, v4

    .line 423
    .line 424
    const v4, 0xd800

    .line 425
    .line 426
    .line 427
    if-lt v8, v4, :cond_17

    .line 428
    .line 429
    and-int/lit16 v8, v8, 0x1fff

    .line 430
    .line 431
    move/from16 v4, v27

    .line 432
    .line 433
    const/16 v27, 0xd

    .line 434
    .line 435
    :goto_f
    add-int/lit8 v29, v4, 0x1

    .line 436
    .line 437
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 438
    .line 439
    .line 440
    move-result v4

    .line 441
    move/from16 v30, v6

    .line 442
    .line 443
    const v6, 0xd800

    .line 444
    .line 445
    .line 446
    if-lt v4, v6, :cond_16

    .line 447
    .line 448
    and-int/lit16 v4, v4, 0x1fff

    .line 449
    .line 450
    shl-int v4, v4, v27

    .line 451
    .line 452
    or-int/2addr v8, v4

    .line 453
    add-int/lit8 v27, v27, 0xd

    .line 454
    .line 455
    move/from16 v4, v29

    .line 456
    .line 457
    move/from16 v6, v30

    .line 458
    .line 459
    goto :goto_f

    .line 460
    :cond_16
    shl-int v4, v4, v27

    .line 461
    .line 462
    or-int/2addr v8, v4

    .line 463
    move/from16 v4, v29

    .line 464
    .line 465
    goto :goto_10

    .line 466
    :cond_17
    move/from16 v30, v6

    .line 467
    .line 468
    move/from16 v4, v27

    .line 469
    .line 470
    :goto_10
    add-int/lit8 v6, v4, 0x1

    .line 471
    .line 472
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C

    .line 473
    .line 474
    .line 475
    move-result v4

    .line 476
    move/from16 v27, v6

    .line 477
    .line 478
    const v6, 0xd800

    .line 479
    .line 480
    .line 481
    if-lt v4, v6, :cond_19

    .line 482
    .line 483
    and-int/lit16 v4, v4, 0x1fff

    .line 484
    .line 485
    move/from16 v6, v27

    .line 486
    .line 487
    const/16 v27, 0xd

    .line 488
    .line 489
    :goto_11
    add-int/lit8 v29, v6, 0x1

    .line 490
    .line 491
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 492
    .line 493
    .line 494
    move-result v6

    .line 495
    move/from16 v31, v4

    .line 496
    .line 497
    const v4, 0xd800

    .line 498
    .line 499
    .line 500
    if-lt v6, v4, :cond_18

    .line 501
    .line 502
    and-int/lit16 v4, v6, 0x1fff

    .line 503
    .line 504
    shl-int v4, v4, v27

    .line 505
    .line 506
    or-int v4, v31, v4

    .line 507
    .line 508
    add-int/lit8 v27, v27, 0xd

    .line 509
    .line 510
    move/from16 v6, v29

    .line 511
    .line 512
    goto :goto_11

    .line 513
    :cond_18
    shl-int v4, v6, v27

    .line 514
    .line 515
    or-int v4, v31, v4

    .line 516
    .line 517
    move/from16 v6, v29

    .line 518
    .line 519
    goto :goto_12

    .line 520
    :cond_19
    move/from16 v6, v27

    .line 521
    .line 522
    :goto_12
    move-object/from16 v27, v7

    .line 523
    .line 524
    and-int/lit16 v7, v4, 0xff

    .line 525
    .line 526
    move/from16 v29, v8

    .line 527
    .line 528
    and-int/lit16 v8, v4, 0x400

    .line 529
    .line 530
    if-eqz v8, :cond_1a

    .line 531
    .line 532
    add-int/lit8 v8, v23, 0x1

    .line 533
    .line 534
    aput v5, v11, v23

    .line 535
    .line 536
    move/from16 v23, v8

    .line 537
    .line 538
    :cond_1a
    const/16 v8, 0x33

    .line 539
    .line 540
    move/from16 v33, v9

    .line 541
    .line 542
    if-lt v7, v8, :cond_23

    .line 543
    .line 544
    add-int/lit8 v8, v6, 0x1

    .line 545
    .line 546
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 547
    .line 548
    .line 549
    move-result v6

    .line 550
    const v9, 0xd800

    .line 551
    .line 552
    .line 553
    if-lt v6, v9, :cond_1c

    .line 554
    .line 555
    and-int/lit16 v6, v6, 0x1fff

    .line 556
    .line 557
    const/16 v34, 0xd

    .line 558
    .line 559
    :goto_13
    add-int/lit8 v35, v8, 0x1

    .line 560
    .line 561
    invoke-virtual {v1, v8}, Ljava/lang/String;->charAt(I)C

    .line 562
    .line 563
    .line 564
    move-result v8

    .line 565
    if-lt v8, v9, :cond_1b

    .line 566
    .line 567
    and-int/lit16 v8, v8, 0x1fff

    .line 568
    .line 569
    shl-int v8, v8, v34

    .line 570
    .line 571
    or-int/2addr v6, v8

    .line 572
    add-int/lit8 v34, v34, 0xd

    .line 573
    .line 574
    move/from16 v8, v35

    .line 575
    .line 576
    const v9, 0xd800

    .line 577
    .line 578
    .line 579
    goto :goto_13

    .line 580
    :cond_1b
    shl-int v8, v8, v34

    .line 581
    .line 582
    or-int/2addr v6, v8

    .line 583
    move/from16 v8, v35

    .line 584
    .line 585
    :cond_1c
    add-int/lit8 v9, v7, -0x33

    .line 586
    .line 587
    move/from16 v34, v6

    .line 588
    .line 589
    const/16 v6, 0x9

    .line 590
    .line 591
    if-eq v9, v6, :cond_1d

    .line 592
    .line 593
    const/16 v6, 0x11

    .line 594
    .line 595
    if-ne v9, v6, :cond_1e

    .line 596
    .line 597
    :cond_1d
    move/from16 v31, v8

    .line 598
    .line 599
    const/4 v6, 0x3

    .line 600
    const/4 v8, 0x2

    .line 601
    const/4 v9, 0x1

    .line 602
    goto :goto_15

    .line 603
    :cond_1e
    const/16 v6, 0xc

    .line 604
    .line 605
    if-ne v9, v6, :cond_20

    .line 606
    .line 607
    and-int/lit8 v6, v21, 0x1

    .line 608
    .line 609
    const/4 v9, 0x1

    .line 610
    move/from16 v31, v8

    .line 611
    .line 612
    if-ne v6, v9, :cond_1f

    .line 613
    .line 614
    const/4 v6, 0x3

    .line 615
    const/4 v8, 0x2

    .line 616
    invoke-static {v5, v6, v8, v9}, La7/g0;->d(IIII)I

    .line 617
    .line 618
    .line 619
    move-result v6

    .line 620
    add-int/lit8 v16, v15, 0x1

    .line 621
    .line 622
    aget-object v15, v27, v15

    .line 623
    .line 624
    aput-object v15, v13, v6

    .line 625
    .line 626
    move/from16 v15, v16

    .line 627
    .line 628
    goto :goto_16

    .line 629
    :cond_1f
    :goto_14
    const/4 v8, 0x2

    .line 630
    goto :goto_16

    .line 631
    :cond_20
    const/4 v9, 0x1

    .line 632
    move/from16 v31, v8

    .line 633
    .line 634
    goto :goto_14

    .line 635
    :goto_15
    invoke-static {v5, v6, v8, v9}, La7/g0;->d(IIII)I

    .line 636
    .line 637
    .line 638
    move-result v6

    .line 639
    add-int/lit8 v9, v15, 0x1

    .line 640
    .line 641
    aget-object v15, v27, v15

    .line 642
    .line 643
    aput-object v15, v13, v6

    .line 644
    .line 645
    move v15, v9

    .line 646
    :goto_16
    mul-int/lit8 v6, v34, 0x2

    .line 647
    .line 648
    aget-object v8, v27, v6

    .line 649
    .line 650
    instance-of v9, v8, Ljava/lang/reflect/Field;

    .line 651
    .line 652
    if-eqz v9, :cond_21

    .line 653
    .line 654
    check-cast v8, Ljava/lang/reflect/Field;

    .line 655
    .line 656
    goto :goto_17

    .line 657
    :cond_21
    check-cast v8, Ljava/lang/String;

    .line 658
    .line 659
    invoke-static {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/r0;->J(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 660
    .line 661
    .line 662
    move-result-object v8

    .line 663
    aput-object v8, v27, v6

    .line 664
    .line 665
    :goto_17
    invoke-virtual {v2, v8}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 666
    .line 667
    .line 668
    move-result-wide v8

    .line 669
    long-to-int v8, v8

    .line 670
    add-int/lit8 v6, v6, 0x1

    .line 671
    .line 672
    aget-object v9, v27, v6

    .line 673
    .line 674
    move/from16 v32, v6

    .line 675
    .line 676
    instance-of v6, v9, Ljava/lang/reflect/Field;

    .line 677
    .line 678
    if-eqz v6, :cond_22

    .line 679
    .line 680
    check-cast v9, Ljava/lang/reflect/Field;

    .line 681
    .line 682
    :goto_18
    move v6, v8

    .line 683
    goto :goto_19

    .line 684
    :cond_22
    check-cast v9, Ljava/lang/String;

    .line 685
    .line 686
    invoke-static {v3, v9}, Lcom/google/crypto/tink/shaded/protobuf/r0;->J(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 687
    .line 688
    .line 689
    move-result-object v9

    .line 690
    aput-object v9, v27, v32

    .line 691
    .line 692
    goto :goto_18

    .line 693
    :goto_19
    invoke-virtual {v2, v9}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 694
    .line 695
    .line 696
    move-result-wide v8

    .line 697
    long-to-int v8, v8

    .line 698
    move/from16 v9, v31

    .line 699
    .line 700
    move/from16 v31, v10

    .line 701
    .line 702
    move v10, v9

    .line 703
    move-object/from16 v16, v11

    .line 704
    .line 705
    move v9, v15

    .line 706
    const/16 v24, 0x2

    .line 707
    .line 708
    move v15, v5

    .line 709
    move v5, v8

    .line 710
    move v8, v6

    .line 711
    const/4 v6, 0x0

    .line 712
    goto/16 :goto_24

    .line 713
    .line 714
    :cond_23
    add-int/lit8 v8, v15, 0x1

    .line 715
    .line 716
    aget-object v9, v27, v15

    .line 717
    .line 718
    check-cast v9, Ljava/lang/String;

    .line 719
    .line 720
    invoke-static {v3, v9}, Lcom/google/crypto/tink/shaded/protobuf/r0;->J(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 721
    .line 722
    .line 723
    move-result-object v9

    .line 724
    move/from16 v34, v8

    .line 725
    .line 726
    const/16 v8, 0x9

    .line 727
    .line 728
    if-eq v7, v8, :cond_24

    .line 729
    .line 730
    const/16 v8, 0x11

    .line 731
    .line 732
    if-ne v7, v8, :cond_25

    .line 733
    .line 734
    :cond_24
    move/from16 v31, v10

    .line 735
    .line 736
    move-object/from16 v16, v11

    .line 737
    .line 738
    const/4 v8, 0x3

    .line 739
    const/4 v10, 0x1

    .line 740
    const/4 v11, 0x2

    .line 741
    goto/16 :goto_1d

    .line 742
    .line 743
    :cond_25
    const/16 v8, 0x1b

    .line 744
    .line 745
    if-eq v7, v8, :cond_26

    .line 746
    .line 747
    const/16 v8, 0x31

    .line 748
    .line 749
    if-ne v7, v8, :cond_27

    .line 750
    .line 751
    :cond_26
    move/from16 v31, v10

    .line 752
    .line 753
    move-object/from16 v16, v11

    .line 754
    .line 755
    const/4 v8, 0x3

    .line 756
    const/4 v10, 0x1

    .line 757
    const/4 v11, 0x2

    .line 758
    goto :goto_1c

    .line 759
    :cond_27
    const/16 v8, 0xc

    .line 760
    .line 761
    if-eq v7, v8, :cond_2b

    .line 762
    .line 763
    const/16 v8, 0x1e

    .line 764
    .line 765
    if-eq v7, v8, :cond_2b

    .line 766
    .line 767
    const/16 v8, 0x2c

    .line 768
    .line 769
    if-ne v7, v8, :cond_28

    .line 770
    .line 771
    goto :goto_1a

    .line 772
    :cond_28
    const/16 v8, 0x32

    .line 773
    .line 774
    if-ne v7, v8, :cond_2a

    .line 775
    .line 776
    add-int/lit8 v8, v25, 0x1

    .line 777
    .line 778
    aput v5, v11, v25

    .line 779
    .line 780
    div-int/lit8 v25, v5, 0x3

    .line 781
    .line 782
    const/16 v24, 0x2

    .line 783
    .line 784
    mul-int/lit8 v25, v25, 0x2

    .line 785
    .line 786
    add-int/lit8 v31, v15, 0x2

    .line 787
    .line 788
    aget-object v32, v27, v34

    .line 789
    .line 790
    aput-object v32, v13, v25

    .line 791
    .line 792
    move/from16 v32, v8

    .line 793
    .line 794
    and-int/lit16 v8, v4, 0x800

    .line 795
    .line 796
    if-eqz v8, :cond_29

    .line 797
    .line 798
    add-int/lit8 v25, v25, 0x1

    .line 799
    .line 800
    add-int/lit8 v8, v15, 0x3

    .line 801
    .line 802
    aget-object v15, v27, v31

    .line 803
    .line 804
    aput-object v15, v13, v25

    .line 805
    .line 806
    move/from16 v31, v10

    .line 807
    .line 808
    move-object/from16 v16, v11

    .line 809
    .line 810
    move/from16 v25, v32

    .line 811
    .line 812
    goto :goto_1f

    .line 813
    :cond_29
    move-object/from16 v16, v11

    .line 814
    .line 815
    move/from16 v8, v31

    .line 816
    .line 817
    move/from16 v25, v32

    .line 818
    .line 819
    move/from16 v31, v10

    .line 820
    .line 821
    goto :goto_1f

    .line 822
    :cond_2a
    move/from16 v31, v10

    .line 823
    .line 824
    move-object/from16 v16, v11

    .line 825
    .line 826
    const/4 v10, 0x1

    .line 827
    goto :goto_1e

    .line 828
    :cond_2b
    :goto_1a
    and-int/lit8 v8, v21, 0x1

    .line 829
    .line 830
    move/from16 v31, v10

    .line 831
    .line 832
    const/4 v10, 0x1

    .line 833
    move-object/from16 v16, v11

    .line 834
    .line 835
    if-ne v8, v10, :cond_2c

    .line 836
    .line 837
    const/4 v8, 0x3

    .line 838
    const/4 v11, 0x2

    .line 839
    invoke-static {v5, v8, v11, v10}, La7/g0;->d(IIII)I

    .line 840
    .line 841
    .line 842
    move-result v8

    .line 843
    add-int/lit8 v15, v15, 0x2

    .line 844
    .line 845
    aget-object v24, v27, v34

    .line 846
    .line 847
    aput-object v24, v13, v8

    .line 848
    .line 849
    :goto_1b
    move v8, v15

    .line 850
    goto :goto_1f

    .line 851
    :goto_1c
    invoke-static {v5, v8, v11, v10}, La7/g0;->d(IIII)I

    .line 852
    .line 853
    .line 854
    move-result v8

    .line 855
    add-int/lit8 v15, v15, 0x2

    .line 856
    .line 857
    aget-object v24, v27, v34

    .line 858
    .line 859
    aput-object v24, v13, v8

    .line 860
    .line 861
    goto :goto_1b

    .line 862
    :goto_1d
    invoke-static {v5, v8, v11, v10}, La7/g0;->d(IIII)I

    .line 863
    .line 864
    .line 865
    move-result v8

    .line 866
    invoke-virtual {v9}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    .line 867
    .line 868
    .line 869
    move-result-object v11

    .line 870
    aput-object v11, v13, v8

    .line 871
    .line 872
    :cond_2c
    :goto_1e
    move/from16 v8, v34

    .line 873
    .line 874
    :goto_1f
    invoke-virtual {v2, v9}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 875
    .line 876
    .line 877
    move-result-wide v10

    .line 878
    long-to-int v9, v10

    .line 879
    and-int/lit8 v10, v21, 0x1

    .line 880
    .line 881
    const/4 v15, 0x1

    .line 882
    if-ne v10, v15, :cond_30

    .line 883
    .line 884
    const/16 v10, 0x11

    .line 885
    .line 886
    if-gt v7, v10, :cond_30

    .line 887
    .line 888
    add-int/lit8 v10, v6, 0x1

    .line 889
    .line 890
    invoke-virtual {v1, v6}, Ljava/lang/String;->charAt(I)C

    .line 891
    .line 892
    .line 893
    move-result v6

    .line 894
    const v11, 0xd800

    .line 895
    .line 896
    .line 897
    if-lt v6, v11, :cond_2e

    .line 898
    .line 899
    and-int/lit16 v6, v6, 0x1fff

    .line 900
    .line 901
    const/16 v19, 0xd

    .line 902
    .line 903
    :goto_20
    add-int/lit8 v32, v10, 0x1

    .line 904
    .line 905
    invoke-virtual {v1, v10}, Ljava/lang/String;->charAt(I)C

    .line 906
    .line 907
    .line 908
    move-result v10

    .line 909
    if-lt v10, v11, :cond_2d

    .line 910
    .line 911
    and-int/lit16 v10, v10, 0x1fff

    .line 912
    .line 913
    shl-int v10, v10, v19

    .line 914
    .line 915
    or-int/2addr v6, v10

    .line 916
    add-int/lit8 v19, v19, 0xd

    .line 917
    .line 918
    move/from16 v10, v32

    .line 919
    .line 920
    goto :goto_20

    .line 921
    :cond_2d
    shl-int v10, v10, v19

    .line 922
    .line 923
    or-int/2addr v6, v10

    .line 924
    move/from16 v10, v32

    .line 925
    .line 926
    :cond_2e
    const/16 v24, 0x2

    .line 927
    .line 928
    mul-int/lit8 v19, v20, 0x2

    .line 929
    .line 930
    div-int/lit8 v32, v6, 0x20

    .line 931
    .line 932
    add-int v32, v32, v19

    .line 933
    .line 934
    aget-object v11, v27, v32

    .line 935
    .line 936
    instance-of v15, v11, Ljava/lang/reflect/Field;

    .line 937
    .line 938
    if-eqz v15, :cond_2f

    .line 939
    .line 940
    check-cast v11, Ljava/lang/reflect/Field;

    .line 941
    .line 942
    :goto_21
    move v15, v5

    .line 943
    move/from16 v32, v6

    .line 944
    .line 945
    goto :goto_22

    .line 946
    :cond_2f
    check-cast v11, Ljava/lang/String;

    .line 947
    .line 948
    invoke-static {v3, v11}, Lcom/google/crypto/tink/shaded/protobuf/r0;->J(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 949
    .line 950
    .line 951
    move-result-object v11

    .line 952
    aput-object v11, v27, v32

    .line 953
    .line 954
    goto :goto_21

    .line 955
    :goto_22
    invoke-virtual {v2, v11}, Lsun/misc/Unsafe;->objectFieldOffset(Ljava/lang/reflect/Field;)J

    .line 956
    .line 957
    .line 958
    move-result-wide v5

    .line 959
    long-to-int v5, v5

    .line 960
    rem-int/lit8 v6, v32, 0x20

    .line 961
    .line 962
    goto :goto_23

    .line 963
    :cond_30
    move v15, v5

    .line 964
    const/16 v24, 0x2

    .line 965
    .line 966
    move v10, v6

    .line 967
    const/4 v5, 0x0

    .line 968
    const/4 v6, 0x0

    .line 969
    :goto_23
    const/16 v11, 0x12

    .line 970
    .line 971
    if-lt v7, v11, :cond_31

    .line 972
    .line 973
    const/16 v11, 0x31

    .line 974
    .line 975
    if-gt v7, v11, :cond_31

    .line 976
    .line 977
    add-int/lit8 v11, v26, 0x1

    .line 978
    .line 979
    aput v9, v16, v26

    .line 980
    .line 981
    move/from16 v26, v9

    .line 982
    .line 983
    move v9, v8

    .line 984
    move/from16 v8, v26

    .line 985
    .line 986
    move/from16 v26, v11

    .line 987
    .line 988
    goto :goto_24

    .line 989
    :cond_31
    move/from16 v36, v9

    .line 990
    .line 991
    move v9, v8

    .line 992
    move/from16 v8, v36

    .line 993
    .line 994
    :goto_24
    add-int/lit8 v11, v15, 0x1

    .line 995
    .line 996
    aput v29, v22, v15

    .line 997
    .line 998
    add-int/lit8 v29, v15, 0x2

    .line 999
    .line 1000
    move-object/from16 v32, v1

    .line 1001
    .line 1002
    and-int/lit16 v1, v4, 0x200

    .line 1003
    .line 1004
    if-eqz v1, :cond_32

    .line 1005
    .line 1006
    const/high16 v1, 0x20000000

    .line 1007
    .line 1008
    goto :goto_25

    .line 1009
    :cond_32
    const/4 v1, 0x0

    .line 1010
    :goto_25
    and-int/lit16 v4, v4, 0x100

    .line 1011
    .line 1012
    if-eqz v4, :cond_33

    .line 1013
    .line 1014
    const/high16 v4, 0x10000000

    .line 1015
    .line 1016
    goto :goto_26

    .line 1017
    :cond_33
    const/4 v4, 0x0

    .line 1018
    :goto_26
    or-int/2addr v1, v4

    .line 1019
    shl-int/lit8 v4, v7, 0x14

    .line 1020
    .line 1021
    or-int/2addr v1, v4

    .line 1022
    or-int/2addr v1, v8

    .line 1023
    aput v1, v22, v11

    .line 1024
    .line 1025
    add-int/lit8 v1, v15, 0x3

    .line 1026
    .line 1027
    shl-int/lit8 v4, v6, 0x14

    .line 1028
    .line 1029
    or-int/2addr v4, v5

    .line 1030
    aput v4, v22, v29

    .line 1031
    .line 1032
    move v5, v1

    .line 1033
    move v15, v9

    .line 1034
    move v8, v10

    .line 1035
    move-object/from16 v11, v16

    .line 1036
    .line 1037
    move-object/from16 v7, v27

    .line 1038
    .line 1039
    move/from16 v4, v28

    .line 1040
    .line 1041
    move/from16 v6, v30

    .line 1042
    .line 1043
    move/from16 v10, v31

    .line 1044
    .line 1045
    move-object/from16 v1, v32

    .line 1046
    .line 1047
    move/from16 v9, v33

    .line 1048
    .line 1049
    goto/16 :goto_e

    .line 1050
    .line 1051
    :cond_34
    move/from16 v30, v6

    .line 1052
    .line 1053
    move/from16 v33, v9

    .line 1054
    .line 1055
    move/from16 v31, v10

    .line 1056
    .line 1057
    move-object/from16 v16, v11

    .line 1058
    .line 1059
    new-instance v4, Lcom/google/crypto/tink/shaded/protobuf/r0;

    .line 1060
    .line 1061
    iget-object v9, v0, Lcom/google/crypto/tink/shaded/protobuf/z0;->a:Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 1062
    .line 1063
    move-object/from16 v15, p2

    .line 1064
    .line 1065
    move-object/from16 v17, p4

    .line 1066
    .line 1067
    move-object/from16 v18, p5

    .line 1068
    .line 1069
    move-object v6, v13

    .line 1070
    move v13, v14

    .line 1071
    move-object/from16 v5, v22

    .line 1072
    .line 1073
    move/from16 v7, v30

    .line 1074
    .line 1075
    move/from16 v8, v33

    .line 1076
    .line 1077
    move-object/from16 v14, p1

    .line 1078
    .line 1079
    move-object/from16 v16, p3

    .line 1080
    .line 1081
    invoke-direct/range {v4 .. v18}, Lcom/google/crypto/tink/shaded/protobuf/r0;-><init>([I[Ljava/lang/Object;IILcom/google/crypto/tink/shaded/protobuf/a;Z[IIILcom/google/crypto/tink/shaded/protobuf/t0;Lcom/google/crypto/tink/shaded/protobuf/j0;Lcom/google/crypto/tink/shaded/protobuf/d1;Lcom/google/crypto/tink/shaded/protobuf/q;Lcom/google/crypto/tink/shaded/protobuf/n0;)V

    .line 1082
    .line 1083
    .line 1084
    return-object v4
.end method

.method public static z(I)J
    .locals 2

    .line 1
    const v0, 0xfffff

    .line 2
    .line 3
    .line 4
    and-int/2addr p0, v0

    .line 5
    int-to-long v0, p0

    .line 6
    return-wide v0
.end method


# virtual methods
.method public final C(JLjava/lang/Object;I)V
    .locals 2

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 2
    .line 3
    invoke-virtual {p0, p4}, Lcom/google/crypto/tink/shaded/protobuf/r0;->n(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p4

    .line 7
    invoke-virtual {v0, p3, p1, p2}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    move-object p0, v1

    .line 17
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 18
    .line 19
    iget-boolean p0, p0, Lcom/google/crypto/tink/shaded/protobuf/m0;->d:Z

    .line 20
    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/m0;->e:Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 24
    .line 25
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/m0;->c()Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-static {p0, v1}, Lcom/google/crypto/tink/shaded/protobuf/n0;->b(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0, p3, p1, p2, p0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    :cond_0
    invoke-static {p4}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    throw p0
.end method

.method public final D(Ljava/lang/Object;[BIIIIIIIJILcom/google/crypto/tink/shaded/protobuf/d;)I
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v8, p6

    .line 6
    .line 7
    move/from16 v2, p7

    .line 8
    .line 9
    move-wide/from16 v9, p10

    .line 10
    .line 11
    move/from16 v3, p12

    .line 12
    .line 13
    sget-object v11, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 14
    .line 15
    add-int/lit8 v4, v3, 0x2

    .line 16
    .line 17
    iget-object v5, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 18
    .line 19
    aget v4, v5, v4

    .line 20
    .line 21
    const v5, 0xfffff

    .line 22
    .line 23
    .line 24
    and-int/2addr v4, v5

    .line 25
    int-to-long v12, v4

    .line 26
    const/4 v4, 0x5

    .line 27
    const/4 v14, 0x0

    .line 28
    const/4 v5, 0x1

    .line 29
    const/4 v6, 0x2

    .line 30
    packed-switch p9, :pswitch_data_0

    .line 31
    .line 32
    .line 33
    :cond_0
    move/from16 v15, p3

    .line 34
    .line 35
    goto/16 :goto_5

    .line 36
    .line 37
    :pswitch_0
    const/4 v4, 0x3

    .line 38
    if-ne v2, v4, :cond_0

    .line 39
    .line 40
    and-int/lit8 v2, p5, -0x8

    .line 41
    .line 42
    or-int/lit8 v6, v2, 0x4

    .line 43
    .line 44
    invoke-virtual {v0, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    move-object/from16 v3, p2

    .line 49
    .line 50
    move/from16 v4, p3

    .line 51
    .line 52
    move/from16 v5, p4

    .line 53
    .line 54
    move-object/from16 v7, p13

    .line 55
    .line 56
    invoke-static/range {v2 .. v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->h(Lcom/google/crypto/tink/shaded/protobuf/a1;[BIIILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    invoke-virtual {v11, v1, v12, v13}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-ne v2, v8, :cond_1

    .line 65
    .line 66
    invoke-virtual {v11, v1, v9, v10}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v14

    .line 70
    :cond_1
    if-nez v14, :cond_2

    .line 71
    .line 72
    iget-object v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 73
    .line 74
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_2
    iget-object v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 79
    .line 80
    invoke-static {v14, v2}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    :goto_0
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 88
    .line 89
    .line 90
    return v0

    .line 91
    :pswitch_1
    move-object/from16 v4, p2

    .line 92
    .line 93
    move/from16 v15, p3

    .line 94
    .line 95
    move-object/from16 v7, p13

    .line 96
    .line 97
    if-nez v2, :cond_9

    .line 98
    .line 99
    invoke-static {v4, v15, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    iget-wide v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 104
    .line 105
    invoke-static {v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 106
    .line 107
    .line 108
    move-result-wide v2

    .line 109
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 117
    .line 118
    .line 119
    return v0

    .line 120
    :pswitch_2
    move-object/from16 v4, p2

    .line 121
    .line 122
    move/from16 v15, p3

    .line 123
    .line 124
    move-object/from16 v7, p13

    .line 125
    .line 126
    if-nez v2, :cond_9

    .line 127
    .line 128
    invoke-static {v4, v15, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    iget v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 133
    .line 134
    invoke-static {v2}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 135
    .line 136
    .line 137
    move-result v2

    .line 138
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 146
    .line 147
    .line 148
    return v0

    .line 149
    :pswitch_3
    move-object/from16 v4, p2

    .line 150
    .line 151
    move/from16 v15, p3

    .line 152
    .line 153
    move-object/from16 v7, p13

    .line 154
    .line 155
    if-nez v2, :cond_9

    .line 156
    .line 157
    invoke-static {v4, v15, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 158
    .line 159
    .line 160
    move-result v2

    .line 161
    iget v4, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 162
    .line 163
    invoke-virtual {v0, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->m(I)V

    .line 164
    .line 165
    .line 166
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    invoke-virtual {v11, v1, v9, v10, v0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 174
    .line 175
    .line 176
    return v2

    .line 177
    :pswitch_4
    move-object/from16 v4, p2

    .line 178
    .line 179
    move/from16 v15, p3

    .line 180
    .line 181
    move-object/from16 v7, p13

    .line 182
    .line 183
    if-ne v2, v6, :cond_9

    .line 184
    .line 185
    invoke-static {v4, v15, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->e([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 186
    .line 187
    .line 188
    move-result v0

    .line 189
    iget-object v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 190
    .line 191
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 195
    .line 196
    .line 197
    return v0

    .line 198
    :pswitch_5
    move-object/from16 v4, p2

    .line 199
    .line 200
    move/from16 v15, p3

    .line 201
    .line 202
    move-object/from16 v7, p13

    .line 203
    .line 204
    if-ne v2, v6, :cond_9

    .line 205
    .line 206
    invoke-virtual {v0, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    move/from16 v5, p4

    .line 211
    .line 212
    invoke-static {v0, v4, v15, v5, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->i(Lcom/google/crypto/tink/shaded/protobuf/a1;[BIILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 213
    .line 214
    .line 215
    move-result v0

    .line 216
    invoke-virtual {v11, v1, v12, v13}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 217
    .line 218
    .line 219
    move-result v2

    .line 220
    if-ne v2, v8, :cond_3

    .line 221
    .line 222
    invoke-virtual {v11, v1, v9, v10}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v14

    .line 226
    :cond_3
    if-nez v14, :cond_4

    .line 227
    .line 228
    iget-object v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 229
    .line 230
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    goto :goto_1

    .line 234
    :cond_4
    iget-object v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 235
    .line 236
    invoke-static {v14, v2}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 237
    .line 238
    .line 239
    move-result-object v2

    .line 240
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    :goto_1
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 244
    .line 245
    .line 246
    return v0

    .line 247
    :pswitch_6
    move-object/from16 v4, p2

    .line 248
    .line 249
    move/from16 v15, p3

    .line 250
    .line 251
    move-object/from16 v7, p13

    .line 252
    .line 253
    if-ne v2, v6, :cond_9

    .line 254
    .line 255
    invoke-static {v4, v15, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 256
    .line 257
    .line 258
    move-result v0

    .line 259
    iget v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 260
    .line 261
    if-nez v2, :cond_5

    .line 262
    .line 263
    const-string v2, ""

    .line 264
    .line 265
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    goto :goto_3

    .line 269
    :cond_5
    const/high16 v3, 0x20000000

    .line 270
    .line 271
    and-int v3, p8, v3

    .line 272
    .line 273
    if-eqz v3, :cond_7

    .line 274
    .line 275
    add-int v3, v0, v2

    .line 276
    .line 277
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/o1;->a:Lcom/google/crypto/tink/shaded/protobuf/q0;

    .line 278
    .line 279
    invoke-virtual {v5, v4, v0, v3}, Lcom/google/crypto/tink/shaded/protobuf/q0;->v([BII)Z

    .line 280
    .line 281
    .line 282
    move-result v3

    .line 283
    if-eqz v3, :cond_6

    .line 284
    .line 285
    goto :goto_2

    .line 286
    :cond_6
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->a()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    throw v0

    .line 291
    :cond_7
    :goto_2
    new-instance v3, Ljava/lang/String;

    .line 292
    .line 293
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 294
    .line 295
    invoke-direct {v3, v4, v0, v2, v5}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v11, v1, v9, v10, v3}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 299
    .line 300
    .line 301
    add-int/2addr v0, v2

    .line 302
    :goto_3
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 303
    .line 304
    .line 305
    return v0

    .line 306
    :pswitch_7
    move-object/from16 v4, p2

    .line 307
    .line 308
    move/from16 v15, p3

    .line 309
    .line 310
    move-object/from16 v7, p13

    .line 311
    .line 312
    if-nez v2, :cond_9

    .line 313
    .line 314
    invoke-static {v4, v15, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 315
    .line 316
    .line 317
    move-result v0

    .line 318
    iget-wide v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 319
    .line 320
    const-wide/16 v6, 0x0

    .line 321
    .line 322
    cmp-long v2, v2, v6

    .line 323
    .line 324
    if-eqz v2, :cond_8

    .line 325
    .line 326
    goto :goto_4

    .line 327
    :cond_8
    const/4 v5, 0x0

    .line 328
    :goto_4
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 329
    .line 330
    .line 331
    move-result-object v2

    .line 332
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 336
    .line 337
    .line 338
    return v0

    .line 339
    :pswitch_8
    move-object/from16 v3, p2

    .line 340
    .line 341
    move/from16 v15, p3

    .line 342
    .line 343
    if-ne v2, v4, :cond_9

    .line 344
    .line 345
    invoke-static {v15, v3}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 346
    .line 347
    .line 348
    move-result v0

    .line 349
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    invoke-virtual {v11, v1, v9, v10, v0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 354
    .line 355
    .line 356
    add-int/lit8 v0, v15, 0x4

    .line 357
    .line 358
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 359
    .line 360
    .line 361
    return v0

    .line 362
    :pswitch_9
    move-object/from16 v3, p2

    .line 363
    .line 364
    move/from16 v15, p3

    .line 365
    .line 366
    if-ne v2, v5, :cond_9

    .line 367
    .line 368
    invoke-static {v15, v3}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 369
    .line 370
    .line 371
    move-result-wide v2

    .line 372
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 373
    .line 374
    .line 375
    move-result-object v0

    .line 376
    invoke-virtual {v11, v1, v9, v10, v0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 377
    .line 378
    .line 379
    add-int/lit8 v0, v15, 0x8

    .line 380
    .line 381
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 382
    .line 383
    .line 384
    return v0

    .line 385
    :pswitch_a
    move-object/from16 v3, p2

    .line 386
    .line 387
    move/from16 v15, p3

    .line 388
    .line 389
    move-object/from16 v7, p13

    .line 390
    .line 391
    if-nez v2, :cond_9

    .line 392
    .line 393
    invoke-static {v3, v15, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 394
    .line 395
    .line 396
    move-result v0

    .line 397
    iget v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 398
    .line 399
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 400
    .line 401
    .line 402
    move-result-object v2

    .line 403
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 404
    .line 405
    .line 406
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 407
    .line 408
    .line 409
    return v0

    .line 410
    :pswitch_b
    move-object/from16 v3, p2

    .line 411
    .line 412
    move/from16 v15, p3

    .line 413
    .line 414
    move-object/from16 v7, p13

    .line 415
    .line 416
    if-nez v2, :cond_9

    .line 417
    .line 418
    invoke-static {v3, v15, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 419
    .line 420
    .line 421
    move-result v0

    .line 422
    iget-wide v2, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 423
    .line 424
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 425
    .line 426
    .line 427
    move-result-object v2

    .line 428
    invoke-virtual {v11, v1, v9, v10, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 429
    .line 430
    .line 431
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 432
    .line 433
    .line 434
    return v0

    .line 435
    :pswitch_c
    move-object/from16 v3, p2

    .line 436
    .line 437
    move/from16 v15, p3

    .line 438
    .line 439
    if-ne v2, v4, :cond_9

    .line 440
    .line 441
    invoke-static {v15, v3}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 442
    .line 443
    .line 444
    move-result v0

    .line 445
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 446
    .line 447
    .line 448
    move-result v0

    .line 449
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 450
    .line 451
    .line 452
    move-result-object v0

    .line 453
    invoke-virtual {v11, v1, v9, v10, v0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 454
    .line 455
    .line 456
    add-int/lit8 v0, v15, 0x4

    .line 457
    .line 458
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 459
    .line 460
    .line 461
    return v0

    .line 462
    :pswitch_d
    move-object/from16 v3, p2

    .line 463
    .line 464
    move/from16 v15, p3

    .line 465
    .line 466
    if-ne v2, v5, :cond_9

    .line 467
    .line 468
    invoke-static {v15, v3}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 469
    .line 470
    .line 471
    move-result-wide v2

    .line 472
    invoke-static {v2, v3}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 473
    .line 474
    .line 475
    move-result-wide v2

    .line 476
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    invoke-virtual {v11, v1, v9, v10, v0}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 481
    .line 482
    .line 483
    add-int/lit8 v0, v15, 0x8

    .line 484
    .line 485
    invoke-virtual {v11, v1, v12, v13, v8}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 486
    .line 487
    .line 488
    return v0

    .line 489
    :cond_9
    :goto_5
    return v15

    .line 490
    nop

    .line 491
    :pswitch_data_0
    .packed-switch 0x33
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_a
        :pswitch_3
        :pswitch_8
        :pswitch_9
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final E(Ljava/lang/Object;[BIIILcom/google/crypto/tink/shaded/protobuf/d;)I
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v1, p2

    .line 6
    .line 7
    move/from16 v4, p4

    .line 8
    .line 9
    move/from16 v14, p5

    .line 10
    .line 11
    move-object/from16 v13, p6

    .line 12
    .line 13
    sget-object v9, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 14
    .line 15
    move/from16 v3, p3

    .line 16
    .line 17
    const/4 v5, -0x1

    .line 18
    const/4 v6, 0x0

    .line 19
    const/4 v7, 0x0

    .line 20
    const/4 v8, -0x1

    .line 21
    const/4 v11, 0x0

    .line 22
    :goto_0
    if-ge v3, v4, :cond_1d

    .line 23
    .line 24
    add-int/lit8 v7, v3, 0x1

    .line 25
    .line 26
    aget-byte v3, v1, v3

    .line 27
    .line 28
    if-gez v3, :cond_0

    .line 29
    .line 30
    invoke-static {v3, v1, v7, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->o(I[BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    iget v3, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 35
    .line 36
    :cond_0
    move/from16 v16, v3

    .line 37
    .line 38
    move v3, v7

    .line 39
    ushr-int/lit8 v7, v16, 0x3

    .line 40
    .line 41
    move/from16 v17, v6

    .line 42
    .line 43
    and-int/lit8 v6, v16, 0x7

    .line 44
    .line 45
    iget v12, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->d:I

    .line 46
    .line 47
    iget v15, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->c:I

    .line 48
    .line 49
    const/4 v10, 0x3

    .line 50
    if-le v7, v5, :cond_2

    .line 51
    .line 52
    div-int/lit8 v5, v17, 0x3

    .line 53
    .line 54
    if-lt v7, v15, :cond_1

    .line 55
    .line 56
    if-gt v7, v12, :cond_1

    .line 57
    .line 58
    invoke-virtual {v0, v7, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->M(II)I

    .line 59
    .line 60
    .line 61
    move-result v5

    .line 62
    goto :goto_1

    .line 63
    :cond_1
    const/4 v5, -0x1

    .line 64
    :goto_1
    const/4 v12, 0x0

    .line 65
    :goto_2
    move v15, v5

    .line 66
    const/4 v5, -0x1

    .line 67
    goto :goto_3

    .line 68
    :cond_2
    if-lt v7, v15, :cond_3

    .line 69
    .line 70
    if-gt v7, v12, :cond_3

    .line 71
    .line 72
    const/4 v12, 0x0

    .line 73
    invoke-virtual {v0, v7, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->M(II)I

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    goto :goto_2

    .line 78
    :cond_3
    const/4 v12, 0x0

    .line 79
    const/4 v5, -0x1

    .line 80
    goto :goto_2

    .line 81
    :goto_3
    if-ne v15, v5, :cond_4

    .line 82
    .line 83
    move-object v6, v0

    .line 84
    move-object v13, v2

    .line 85
    move/from16 v17, v7

    .line 86
    .line 87
    move-object/from16 v18, v9

    .line 88
    .line 89
    move/from16 v19, v12

    .line 90
    .line 91
    move/from16 v2, v16

    .line 92
    .line 93
    const/4 v15, 0x0

    .line 94
    goto/16 :goto_17

    .line 95
    .line 96
    :cond_4
    add-int/lit8 v5, v15, 0x1

    .line 97
    .line 98
    iget-object v12, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 99
    .line 100
    aget v5, v12, v5

    .line 101
    .line 102
    invoke-static {v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 103
    .line 104
    .line 105
    move-result v10

    .line 106
    const v19, 0xfffff

    .line 107
    .line 108
    .line 109
    and-int v1, v5, v19

    .line 110
    .line 111
    move-object/from16 v20, v12

    .line 112
    .line 113
    int-to-long v12, v1

    .line 114
    const/16 v1, 0x11

    .line 115
    .line 116
    move/from16 v21, v3

    .line 117
    .line 118
    if-gt v10, v1, :cond_11

    .line 119
    .line 120
    add-int/lit8 v1, v15, 0x2

    .line 121
    .line 122
    aget v1, v20, v1

    .line 123
    .line 124
    ushr-int/lit8 v20, v1, 0x14

    .line 125
    .line 126
    const/4 v3, 0x1

    .line 127
    shl-int v20, v3, v20

    .line 128
    .line 129
    and-int v1, v1, v19

    .line 130
    .line 131
    if-eq v1, v8, :cond_6

    .line 132
    .line 133
    const/4 v3, -0x1

    .line 134
    if-eq v8, v3, :cond_5

    .line 135
    .line 136
    int-to-long v3, v8

    .line 137
    invoke-virtual {v9, v2, v3, v4, v11}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 138
    .line 139
    .line 140
    :cond_5
    int-to-long v3, v1

    .line 141
    invoke-virtual {v9, v2, v3, v4}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 142
    .line 143
    .line 144
    move-result v11

    .line 145
    move/from16 v23, v11

    .line 146
    .line 147
    move v11, v1

    .line 148
    goto :goto_4

    .line 149
    :cond_6
    move/from16 v23, v11

    .line 150
    .line 151
    move v11, v8

    .line 152
    :goto_4
    const/4 v1, 0x5

    .line 153
    packed-switch v10, :pswitch_data_0

    .line 154
    .line 155
    .line 156
    move/from16 v8, p4

    .line 157
    .line 158
    move-object/from16 v10, p6

    .line 159
    .line 160
    move-object v13, v2

    .line 161
    move/from16 v17, v7

    .line 162
    .line 163
    move-object v12, v9

    .line 164
    move/from16 v9, v21

    .line 165
    .line 166
    move-object/from16 v7, p2

    .line 167
    .line 168
    goto/16 :goto_11

    .line 169
    .line 170
    :pswitch_0
    const/4 v1, 0x3

    .line 171
    if-ne v6, v1, :cond_8

    .line 172
    .line 173
    shl-int/lit8 v1, v7, 0x3

    .line 174
    .line 175
    or-int/lit8 v1, v1, 0x4

    .line 176
    .line 177
    invoke-virtual {v0, v15}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 178
    .line 179
    .line 180
    move-result-object v3

    .line 181
    move-object/from16 v4, p2

    .line 182
    .line 183
    move/from16 v6, p4

    .line 184
    .line 185
    move-object/from16 v8, p6

    .line 186
    .line 187
    move/from16 v17, v7

    .line 188
    .line 189
    move/from16 v5, v21

    .line 190
    .line 191
    move v7, v1

    .line 192
    invoke-static/range {v3 .. v8}, Lcom/google/crypto/tink/shaded/protobuf/q0;->h(Lcom/google/crypto/tink/shaded/protobuf/a1;[BIIILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 193
    .line 194
    .line 195
    move-result v3

    .line 196
    move-object v7, v4

    .line 197
    move-object v10, v8

    .line 198
    move v8, v6

    .line 199
    and-int v1, v23, v20

    .line 200
    .line 201
    if-nez v1, :cond_7

    .line 202
    .line 203
    iget-object v1, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 204
    .line 205
    invoke-virtual {v9, v2, v12, v13, v1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    goto :goto_5

    .line 209
    :cond_7
    invoke-virtual {v9, v2, v12, v13}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    iget-object v4, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 214
    .line 215
    invoke-static {v1, v4}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    invoke-virtual {v9, v2, v12, v13, v1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    :goto_5
    or-int v1, v23, v20

    .line 223
    .line 224
    :goto_6
    move v4, v8

    .line 225
    move-object v13, v10

    .line 226
    move v8, v11

    .line 227
    :goto_7
    move v6, v15

    .line 228
    move/from16 v5, v17

    .line 229
    .line 230
    :goto_8
    move v11, v1

    .line 231
    move-object v1, v7

    .line 232
    :goto_9
    move/from16 v7, v16

    .line 233
    .line 234
    goto/16 :goto_0

    .line 235
    .line 236
    :cond_8
    move/from16 v8, p4

    .line 237
    .line 238
    move-object/from16 v10, p6

    .line 239
    .line 240
    move/from16 v17, v7

    .line 241
    .line 242
    move-object/from16 v7, p2

    .line 243
    .line 244
    move-object v13, v2

    .line 245
    move-object v12, v9

    .line 246
    move/from16 v9, v21

    .line 247
    .line 248
    goto/16 :goto_11

    .line 249
    .line 250
    :pswitch_1
    move/from16 v8, p4

    .line 251
    .line 252
    move-object/from16 v10, p6

    .line 253
    .line 254
    move/from16 v17, v7

    .line 255
    .line 256
    move/from16 v3, v21

    .line 257
    .line 258
    move-object/from16 v7, p2

    .line 259
    .line 260
    if-nez v6, :cond_9

    .line 261
    .line 262
    invoke-static {v7, v3, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 263
    .line 264
    .line 265
    move-result v19

    .line 266
    iget-wide v3, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 267
    .line 268
    invoke-static {v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 269
    .line 270
    .line 271
    move-result-wide v5

    .line 272
    move-object v1, v9

    .line 273
    move-wide v3, v12

    .line 274
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 275
    .line 276
    .line 277
    move-object v4, v1

    .line 278
    or-int v1, v23, v20

    .line 279
    .line 280
    move-object v9, v4

    .line 281
    move v4, v8

    .line 282
    move-object v13, v10

    .line 283
    move v8, v11

    .line 284
    move v6, v15

    .line 285
    move/from16 v5, v17

    .line 286
    .line 287
    move/from16 v3, v19

    .line 288
    .line 289
    goto :goto_8

    .line 290
    :cond_9
    move-object v13, v2

    .line 291
    move-object v12, v9

    .line 292
    move v9, v3

    .line 293
    goto/16 :goto_11

    .line 294
    .line 295
    :pswitch_2
    move/from16 v8, p4

    .line 296
    .line 297
    move-object/from16 v10, p6

    .line 298
    .line 299
    move/from16 v17, v7

    .line 300
    .line 301
    move-object v4, v9

    .line 302
    move/from16 v3, v21

    .line 303
    .line 304
    move-object/from16 v7, p2

    .line 305
    .line 306
    if-nez v6, :cond_a

    .line 307
    .line 308
    invoke-static {v7, v3, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 309
    .line 310
    .line 311
    move-result v3

    .line 312
    iget v1, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 313
    .line 314
    invoke-static {v1}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 315
    .line 316
    .line 317
    move-result v1

    .line 318
    invoke-virtual {v4, v2, v12, v13, v1}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 319
    .line 320
    .line 321
    :goto_a
    or-int v1, v23, v20

    .line 322
    .line 323
    move-object v9, v4

    .line 324
    goto :goto_6

    .line 325
    :cond_a
    move-object v13, v2

    .line 326
    move v9, v3

    .line 327
    :goto_b
    move-object v12, v4

    .line 328
    goto/16 :goto_11

    .line 329
    .line 330
    :pswitch_3
    move/from16 v8, p4

    .line 331
    .line 332
    move-object/from16 v10, p6

    .line 333
    .line 334
    move/from16 v17, v7

    .line 335
    .line 336
    move-object v4, v9

    .line 337
    move/from16 v3, v21

    .line 338
    .line 339
    move-object/from16 v7, p2

    .line 340
    .line 341
    if-nez v6, :cond_a

    .line 342
    .line 343
    invoke-static {v7, v3, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 344
    .line 345
    .line 346
    move-result v3

    .line 347
    iget v1, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 348
    .line 349
    invoke-virtual {v0, v15}, Lcom/google/crypto/tink/shaded/protobuf/r0;->m(I)V

    .line 350
    .line 351
    .line 352
    invoke-virtual {v4, v2, v12, v13, v1}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 353
    .line 354
    .line 355
    goto :goto_a

    .line 356
    :pswitch_4
    move/from16 v8, p4

    .line 357
    .line 358
    move-object/from16 v10, p6

    .line 359
    .line 360
    move/from16 v17, v7

    .line 361
    .line 362
    move-object v4, v9

    .line 363
    move/from16 v3, v21

    .line 364
    .line 365
    const/4 v1, 0x2

    .line 366
    move-object/from16 v7, p2

    .line 367
    .line 368
    if-ne v6, v1, :cond_a

    .line 369
    .line 370
    invoke-static {v7, v3, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->e([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 371
    .line 372
    .line 373
    move-result v3

    .line 374
    iget-object v1, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 375
    .line 376
    invoke-virtual {v4, v2, v12, v13, v1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 377
    .line 378
    .line 379
    goto :goto_a

    .line 380
    :pswitch_5
    move/from16 v8, p4

    .line 381
    .line 382
    move-object/from16 v10, p6

    .line 383
    .line 384
    move/from16 v17, v7

    .line 385
    .line 386
    move-object v4, v9

    .line 387
    move/from16 v3, v21

    .line 388
    .line 389
    const/4 v1, 0x2

    .line 390
    move-object/from16 v7, p2

    .line 391
    .line 392
    if-ne v6, v1, :cond_a

    .line 393
    .line 394
    invoke-virtual {v0, v15}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 395
    .line 396
    .line 397
    move-result-object v1

    .line 398
    invoke-static {v1, v7, v3, v8, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->i(Lcom/google/crypto/tink/shaded/protobuf/a1;[BIILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 399
    .line 400
    .line 401
    move-result v3

    .line 402
    and-int v1, v23, v20

    .line 403
    .line 404
    if-nez v1, :cond_b

    .line 405
    .line 406
    iget-object v1, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 407
    .line 408
    invoke-virtual {v4, v2, v12, v13, v1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 409
    .line 410
    .line 411
    goto :goto_a

    .line 412
    :cond_b
    invoke-virtual {v4, v2, v12, v13}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 413
    .line 414
    .line 415
    move-result-object v1

    .line 416
    iget-object v5, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 417
    .line 418
    invoke-static {v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 419
    .line 420
    .line 421
    move-result-object v1

    .line 422
    invoke-virtual {v4, v2, v12, v13, v1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 423
    .line 424
    .line 425
    goto :goto_a

    .line 426
    :pswitch_6
    move/from16 v8, p4

    .line 427
    .line 428
    move-object/from16 v10, p6

    .line 429
    .line 430
    move/from16 v17, v7

    .line 431
    .line 432
    move-object v4, v9

    .line 433
    move/from16 v3, v21

    .line 434
    .line 435
    const/4 v1, 0x2

    .line 436
    move-object/from16 v7, p2

    .line 437
    .line 438
    if-ne v6, v1, :cond_a

    .line 439
    .line 440
    const/high16 v1, 0x20000000

    .line 441
    .line 442
    and-int/2addr v1, v5

    .line 443
    if-nez v1, :cond_c

    .line 444
    .line 445
    invoke-static {v7, v3, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->k([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 446
    .line 447
    .line 448
    move-result v1

    .line 449
    :goto_c
    move v3, v1

    .line 450
    goto :goto_d

    .line 451
    :cond_c
    invoke-static {v7, v3, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->l([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 452
    .line 453
    .line 454
    move-result v1

    .line 455
    goto :goto_c

    .line 456
    :goto_d
    iget-object v1, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 457
    .line 458
    invoke-virtual {v4, v2, v12, v13, v1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 459
    .line 460
    .line 461
    goto/16 :goto_a

    .line 462
    .line 463
    :pswitch_7
    move/from16 v8, p4

    .line 464
    .line 465
    move-object/from16 v10, p6

    .line 466
    .line 467
    move/from16 v17, v7

    .line 468
    .line 469
    move-object v4, v9

    .line 470
    move/from16 v3, v21

    .line 471
    .line 472
    move-object/from16 v7, p2

    .line 473
    .line 474
    if-nez v6, :cond_a

    .line 475
    .line 476
    invoke-static {v7, v3, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 477
    .line 478
    .line 479
    move-result v3

    .line 480
    iget-wide v5, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 481
    .line 482
    const-wide/16 v21, 0x0

    .line 483
    .line 484
    cmp-long v1, v5, v21

    .line 485
    .line 486
    if-eqz v1, :cond_d

    .line 487
    .line 488
    const/4 v1, 0x1

    .line 489
    goto :goto_e

    .line 490
    :cond_d
    const/4 v1, 0x0

    .line 491
    :goto_e
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 492
    .line 493
    invoke-virtual {v5, v2, v12, v13, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->k(Ljava/lang/Object;JZ)V

    .line 494
    .line 495
    .line 496
    goto/16 :goto_a

    .line 497
    .line 498
    :pswitch_8
    move/from16 v8, p4

    .line 499
    .line 500
    move-object/from16 v10, p6

    .line 501
    .line 502
    move/from16 v17, v7

    .line 503
    .line 504
    move-object v4, v9

    .line 505
    move/from16 v3, v21

    .line 506
    .line 507
    move-object/from16 v7, p2

    .line 508
    .line 509
    if-ne v6, v1, :cond_a

    .line 510
    .line 511
    invoke-static {v3, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 512
    .line 513
    .line 514
    move-result v1

    .line 515
    invoke-virtual {v4, v2, v12, v13, v1}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 516
    .line 517
    .line 518
    add-int/lit8 v3, v3, 0x4

    .line 519
    .line 520
    goto/16 :goto_a

    .line 521
    .line 522
    :pswitch_9
    move/from16 v8, p4

    .line 523
    .line 524
    move-object/from16 v10, p6

    .line 525
    .line 526
    move/from16 v17, v7

    .line 527
    .line 528
    move-object v4, v9

    .line 529
    move/from16 v3, v21

    .line 530
    .line 531
    const/4 v1, 0x1

    .line 532
    move-object/from16 v7, p2

    .line 533
    .line 534
    if-ne v6, v1, :cond_e

    .line 535
    .line 536
    invoke-static {v3, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 537
    .line 538
    .line 539
    move-result-wide v5

    .line 540
    move v9, v3

    .line 541
    move-object v1, v4

    .line 542
    move-wide v3, v12

    .line 543
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 544
    .line 545
    .line 546
    add-int/lit8 v3, v9, 0x8

    .line 547
    .line 548
    or-int v4, v23, v20

    .line 549
    .line 550
    move v5, v11

    .line 551
    move v11, v4

    .line 552
    move v4, v8

    .line 553
    move v8, v5

    .line 554
    move-object v9, v1

    .line 555
    move-object v1, v7

    .line 556
    move-object v13, v10

    .line 557
    move v6, v15

    .line 558
    move/from16 v7, v16

    .line 559
    .line 560
    :goto_f
    move/from16 v5, v17

    .line 561
    .line 562
    goto/16 :goto_0

    .line 563
    .line 564
    :cond_e
    move v9, v3

    .line 565
    move-object v13, v2

    .line 566
    goto/16 :goto_b

    .line 567
    .line 568
    :pswitch_a
    move/from16 v8, p4

    .line 569
    .line 570
    move-object/from16 v10, p6

    .line 571
    .line 572
    move/from16 v17, v7

    .line 573
    .line 574
    move-object v1, v9

    .line 575
    move-wide v3, v12

    .line 576
    move/from16 v9, v21

    .line 577
    .line 578
    move-object/from16 v7, p2

    .line 579
    .line 580
    if-nez v6, :cond_f

    .line 581
    .line 582
    invoke-static {v7, v9, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 583
    .line 584
    .line 585
    move-result v5

    .line 586
    iget v6, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 587
    .line 588
    invoke-virtual {v1, v2, v3, v4, v6}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 589
    .line 590
    .line 591
    or-int v3, v23, v20

    .line 592
    .line 593
    move-object v9, v1

    .line 594
    move-object v1, v7

    .line 595
    move v4, v8

    .line 596
    move-object v13, v10

    .line 597
    move v8, v11

    .line 598
    move v6, v15

    .line 599
    move/from16 v7, v16

    .line 600
    .line 601
    move v11, v3

    .line 602
    move v3, v5

    .line 603
    goto :goto_f

    .line 604
    :cond_f
    move-object v12, v1

    .line 605
    :cond_10
    move-object v13, v2

    .line 606
    goto/16 :goto_11

    .line 607
    .line 608
    :pswitch_b
    move/from16 v8, p4

    .line 609
    .line 610
    move-object/from16 v10, p6

    .line 611
    .line 612
    move/from16 v17, v7

    .line 613
    .line 614
    move-object v1, v9

    .line 615
    move-wide v3, v12

    .line 616
    move/from16 v9, v21

    .line 617
    .line 618
    move-object/from16 v7, p2

    .line 619
    .line 620
    if-nez v6, :cond_f

    .line 621
    .line 622
    invoke-static {v7, v9, v10}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 623
    .line 624
    .line 625
    move-result v9

    .line 626
    iget-wide v5, v10, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 627
    .line 628
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 629
    .line 630
    .line 631
    move-object v12, v1

    .line 632
    or-int v1, v23, v20

    .line 633
    .line 634
    move v4, v8

    .line 635
    move v3, v9

    .line 636
    :goto_10
    move-object v13, v10

    .line 637
    move v8, v11

    .line 638
    move-object v9, v12

    .line 639
    goto/16 :goto_7

    .line 640
    .line 641
    :pswitch_c
    move/from16 v8, p4

    .line 642
    .line 643
    move-object/from16 v10, p6

    .line 644
    .line 645
    move/from16 v17, v7

    .line 646
    .line 647
    move-wide v3, v12

    .line 648
    move-object/from16 v7, p2

    .line 649
    .line 650
    move-object v12, v9

    .line 651
    move/from16 v9, v21

    .line 652
    .line 653
    if-ne v6, v1, :cond_10

    .line 654
    .line 655
    invoke-static {v9, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 656
    .line 657
    .line 658
    move-result v1

    .line 659
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 660
    .line 661
    .line 662
    move-result v1

    .line 663
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 664
    .line 665
    invoke-virtual {v5, v2, v3, v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->n(Ljava/lang/Object;JF)V

    .line 666
    .line 667
    .line 668
    add-int/lit8 v3, v9, 0x4

    .line 669
    .line 670
    or-int v1, v23, v20

    .line 671
    .line 672
    move v4, v8

    .line 673
    goto :goto_10

    .line 674
    :pswitch_d
    move/from16 v8, p4

    .line 675
    .line 676
    move-object/from16 v10, p6

    .line 677
    .line 678
    move/from16 v17, v7

    .line 679
    .line 680
    move-wide v3, v12

    .line 681
    const/4 v1, 0x1

    .line 682
    move-object/from16 v7, p2

    .line 683
    .line 684
    move-object v12, v9

    .line 685
    move/from16 v9, v21

    .line 686
    .line 687
    if-ne v6, v1, :cond_10

    .line 688
    .line 689
    invoke-static {v9, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 690
    .line 691
    .line 692
    move-result-wide v5

    .line 693
    invoke-static {v5, v6}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 694
    .line 695
    .line 696
    move-result-wide v5

    .line 697
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 698
    .line 699
    invoke-virtual/range {v1 .. v6}, Lcom/google/crypto/tink/shaded/protobuf/k1;->m(Ljava/lang/Object;JD)V

    .line 700
    .line 701
    .line 702
    move-object v13, v2

    .line 703
    add-int/lit8 v3, v9, 0x8

    .line 704
    .line 705
    or-int v1, v23, v20

    .line 706
    .line 707
    move v4, v8

    .line 708
    move v8, v11

    .line 709
    move-object v9, v12

    .line 710
    move v6, v15

    .line 711
    move/from16 v5, v17

    .line 712
    .line 713
    move v11, v1

    .line 714
    move-object v1, v7

    .line 715
    move-object v13, v10

    .line 716
    goto/16 :goto_9

    .line 717
    .line 718
    :goto_11
    move-object v6, v0

    .line 719
    move v3, v9

    .line 720
    move v8, v11

    .line 721
    move-object/from16 v18, v12

    .line 722
    .line 723
    move v12, v15

    .line 724
    move/from16 v2, v16

    .line 725
    .line 726
    move/from16 v11, v23

    .line 727
    .line 728
    const/4 v15, 0x0

    .line 729
    const/16 v19, 0x0

    .line 730
    .line 731
    goto/16 :goto_17

    .line 732
    .line 733
    :cond_11
    move/from16 v17, v7

    .line 734
    .line 735
    move-wide v3, v12

    .line 736
    move-object/from16 v7, p2

    .line 737
    .line 738
    move-object v13, v2

    .line 739
    move-object v12, v9

    .line 740
    move/from16 v9, v21

    .line 741
    .line 742
    const/16 v1, 0x1b

    .line 743
    .line 744
    if-ne v10, v1, :cond_15

    .line 745
    .line 746
    const/4 v1, 0x2

    .line 747
    if-ne v6, v1, :cond_14

    .line 748
    .line 749
    invoke-virtual {v12, v13, v3, v4}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 750
    .line 751
    .line 752
    move-result-object v1

    .line 753
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 754
    .line 755
    move-object v2, v1

    .line 756
    check-cast v2, Lcom/google/crypto/tink/shaded/protobuf/b;

    .line 757
    .line 758
    iget-boolean v2, v2, Lcom/google/crypto/tink/shaded/protobuf/b;->d:Z

    .line 759
    .line 760
    if-nez v2, :cond_13

    .line 761
    .line 762
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 763
    .line 764
    .line 765
    move-result v2

    .line 766
    if-nez v2, :cond_12

    .line 767
    .line 768
    const/16 v2, 0xa

    .line 769
    .line 770
    goto :goto_12

    .line 771
    :cond_12
    mul-int/lit8 v2, v2, 0x2

    .line 772
    .line 773
    :goto_12
    invoke-interface {v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/a0;->a(I)Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 774
    .line 775
    .line 776
    move-result-object v1

    .line 777
    invoke-virtual {v12, v13, v3, v4, v1}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 778
    .line 779
    .line 780
    :cond_13
    move-object v6, v1

    .line 781
    invoke-virtual {v0, v15}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 782
    .line 783
    .line 784
    move-result-object v1

    .line 785
    move/from16 v5, p4

    .line 786
    .line 787
    move-object v3, v7

    .line 788
    move v4, v9

    .line 789
    move/from16 v2, v16

    .line 790
    .line 791
    move-object/from16 v7, p6

    .line 792
    .line 793
    invoke-static/range {v1 .. v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->j(Lcom/google/crypto/tink/shaded/protobuf/a1;I[BIILcom/google/crypto/tink/shaded/protobuf/a0;Lcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 794
    .line 795
    .line 796
    move-result v1

    .line 797
    move/from16 v4, p4

    .line 798
    .line 799
    move v3, v1

    .line 800
    move v7, v2

    .line 801
    move-object v9, v12

    .line 802
    move-object v2, v13

    .line 803
    move v6, v15

    .line 804
    move/from16 v5, v17

    .line 805
    .line 806
    move-object/from16 v1, p2

    .line 807
    .line 808
    :goto_13
    move-object/from16 v13, p6

    .line 809
    .line 810
    goto/16 :goto_0

    .line 811
    .line 812
    :cond_14
    move/from16 p3, v8

    .line 813
    .line 814
    move v3, v9

    .line 815
    move-object/from16 v18, v12

    .line 816
    .line 817
    move-object v1, v13

    .line 818
    move v12, v15

    .line 819
    move/from16 v2, v16

    .line 820
    .line 821
    const/4 v15, 0x0

    .line 822
    const/16 v19, 0x0

    .line 823
    .line 824
    move/from16 v16, v11

    .line 825
    .line 826
    goto/16 :goto_14

    .line 827
    .line 828
    :cond_15
    move/from16 v2, v16

    .line 829
    .line 830
    const/16 v1, 0x31

    .line 831
    .line 832
    if-gt v10, v1, :cond_17

    .line 833
    .line 834
    move v1, v8

    .line 835
    move/from16 v21, v9

    .line 836
    .line 837
    int-to-long v8, v5

    .line 838
    move/from16 p3, v1

    .line 839
    .line 840
    move v5, v2

    .line 841
    move/from16 v16, v11

    .line 842
    .line 843
    move-object/from16 v18, v12

    .line 844
    .line 845
    move-object v1, v13

    .line 846
    move v7, v15

    .line 847
    const/4 v15, 0x0

    .line 848
    const/16 v19, 0x0

    .line 849
    .line 850
    move-object/from16 v2, p2

    .line 851
    .line 852
    move-object/from16 v13, p6

    .line 853
    .line 854
    move-wide v11, v3

    .line 855
    move/from16 v3, v21

    .line 856
    .line 857
    move/from16 v4, p4

    .line 858
    .line 859
    invoke-virtual/range {v0 .. v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->G(Ljava/lang/Object;[BIIIIIJIJLcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 860
    .line 861
    .line 862
    move-result v6

    .line 863
    move v2, v5

    .line 864
    move v12, v7

    .line 865
    if-eq v6, v3, :cond_16

    .line 866
    .line 867
    move/from16 v8, p3

    .line 868
    .line 869
    move/from16 v4, p4

    .line 870
    .line 871
    move-object/from16 v13, p6

    .line 872
    .line 873
    move v7, v2

    .line 874
    move v3, v6

    .line 875
    move v6, v12

    .line 876
    move/from16 v11, v16

    .line 877
    .line 878
    move/from16 v5, v17

    .line 879
    .line 880
    move-object/from16 v9, v18

    .line 881
    .line 882
    move-object v2, v1

    .line 883
    move-object/from16 v1, p2

    .line 884
    .line 885
    goto/16 :goto_0

    .line 886
    .line 887
    :cond_16
    move/from16 v8, p3

    .line 888
    .line 889
    move-object v13, v1

    .line 890
    move v3, v6

    .line 891
    move/from16 v11, v16

    .line 892
    .line 893
    move-object v6, v0

    .line 894
    goto/16 :goto_17

    .line 895
    .line 896
    :cond_17
    move/from16 p3, v8

    .line 897
    .line 898
    move/from16 v16, v11

    .line 899
    .line 900
    move-object/from16 v18, v12

    .line 901
    .line 902
    move-object v1, v13

    .line 903
    move v12, v15

    .line 904
    const/4 v15, 0x0

    .line 905
    const/16 v19, 0x0

    .line 906
    .line 907
    move-wide/from16 v24, v3

    .line 908
    .line 909
    move v3, v9

    .line 910
    move v9, v10

    .line 911
    move-wide/from16 v10, v24

    .line 912
    .line 913
    const/16 v4, 0x32

    .line 914
    .line 915
    if-ne v9, v4, :cond_19

    .line 916
    .line 917
    const/4 v4, 0x2

    .line 918
    if-eq v6, v4, :cond_18

    .line 919
    .line 920
    :goto_14
    move/from16 v8, p3

    .line 921
    .line 922
    move-object v6, v0

    .line 923
    move-object v13, v1

    .line 924
    :goto_15
    move/from16 v11, v16

    .line 925
    .line 926
    goto :goto_17

    .line 927
    :cond_18
    invoke-virtual {v0, v10, v11, v1, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->C(JLjava/lang/Object;I)V

    .line 928
    .line 929
    .line 930
    throw v15

    .line 931
    :cond_19
    move/from16 v4, p4

    .line 932
    .line 933
    move-object/from16 v13, p6

    .line 934
    .line 935
    move v8, v5

    .line 936
    move v7, v6

    .line 937
    move/from16 v6, v17

    .line 938
    .line 939
    move v5, v2

    .line 940
    move-object/from16 v2, p2

    .line 941
    .line 942
    invoke-virtual/range {v0 .. v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->D(Ljava/lang/Object;[BIIIIIIIJILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 943
    .line 944
    .line 945
    move-result v7

    .line 946
    move-object v13, v1

    .line 947
    move v2, v5

    .line 948
    move-object v6, v0

    .line 949
    if-eq v7, v3, :cond_1a

    .line 950
    .line 951
    move-object/from16 v1, p2

    .line 952
    .line 953
    move/from16 v8, p3

    .line 954
    .line 955
    move/from16 v4, p4

    .line 956
    .line 957
    move-object v0, v6

    .line 958
    move v3, v7

    .line 959
    move v6, v12

    .line 960
    move/from16 v11, v16

    .line 961
    .line 962
    move/from16 v5, v17

    .line 963
    .line 964
    move-object/from16 v9, v18

    .line 965
    .line 966
    move v7, v2

    .line 967
    :goto_16
    move-object v2, v13

    .line 968
    goto/16 :goto_13

    .line 969
    .line 970
    :cond_1a
    move/from16 v8, p3

    .line 971
    .line 972
    move v3, v7

    .line 973
    goto :goto_15

    .line 974
    :goto_17
    if-ne v2, v14, :cond_1b

    .line 975
    .line 976
    if-eqz v14, :cond_1b

    .line 977
    .line 978
    move/from16 v4, p4

    .line 979
    .line 980
    move v7, v2

    .line 981
    :goto_18
    const/4 v5, -0x1

    .line 982
    goto :goto_19

    .line 983
    :cond_1b
    move-object v0, v13

    .line 984
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 985
    .line 986
    iget-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 987
    .line 988
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/c1;->f:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 989
    .line 990
    if-ne v1, v4, :cond_1c

    .line 991
    .line 992
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c1;->b()Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 993
    .line 994
    .line 995
    move-result-object v1

    .line 996
    iput-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 997
    .line 998
    :cond_1c
    move-object/from16 v5, p6

    .line 999
    .line 1000
    move-object v4, v1

    .line 1001
    move v0, v2

    .line 1002
    move v2, v3

    .line 1003
    move-object/from16 v1, p2

    .line 1004
    .line 1005
    move/from16 v3, p4

    .line 1006
    .line 1007
    invoke-static/range {v0 .. v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->m(I[BIILcom/google/crypto/tink/shaded/protobuf/c1;Lcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 1008
    .line 1009
    .line 1010
    move-result v2

    .line 1011
    move v5, v0

    .line 1012
    move-object/from16 v1, p2

    .line 1013
    .line 1014
    move v4, v3

    .line 1015
    move v7, v5

    .line 1016
    move-object v0, v6

    .line 1017
    move v6, v12

    .line 1018
    move/from16 v5, v17

    .line 1019
    .line 1020
    move-object/from16 v9, v18

    .line 1021
    .line 1022
    move v3, v2

    .line 1023
    goto :goto_16

    .line 1024
    :cond_1d
    move-object v6, v0

    .line 1025
    move-object v13, v2

    .line 1026
    move/from16 p3, v8

    .line 1027
    .line 1028
    move-object/from16 v18, v9

    .line 1029
    .line 1030
    move/from16 v16, v11

    .line 1031
    .line 1032
    const/4 v15, 0x0

    .line 1033
    goto :goto_18

    .line 1034
    :goto_19
    if-eq v8, v5, :cond_1e

    .line 1035
    .line 1036
    int-to-long v0, v8

    .line 1037
    move-object/from16 v12, v18

    .line 1038
    .line 1039
    invoke-virtual {v12, v13, v0, v1, v11}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 1040
    .line 1041
    .line 1042
    :cond_1e
    iget v0, v6, Lcom/google/crypto/tink/shaded/protobuf/r0;->i:I

    .line 1043
    .line 1044
    :goto_1a
    iget v1, v6, Lcom/google/crypto/tink/shaded/protobuf/r0;->j:I

    .line 1045
    .line 1046
    if-ge v0, v1, :cond_1f

    .line 1047
    .line 1048
    iget-object v1, v6, Lcom/google/crypto/tink/shaded/protobuf/r0;->h:[I

    .line 1049
    .line 1050
    aget v1, v1, v0

    .line 1051
    .line 1052
    invoke-virtual {v6, v1, v13, v15}, Lcom/google/crypto/tink/shaded/protobuf/r0;->l(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1053
    .line 1054
    .line 1055
    add-int/lit8 v0, v0, 0x1

    .line 1056
    .line 1057
    goto :goto_1a

    .line 1058
    :cond_1f
    if-nez v14, :cond_21

    .line 1059
    .line 1060
    if-ne v3, v4, :cond_20

    .line 1061
    .line 1062
    goto :goto_1b

    .line 1063
    :cond_20
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->e()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 1064
    .line 1065
    .line 1066
    move-result-object v0

    .line 1067
    throw v0

    .line 1068
    :cond_21
    if-gt v3, v4, :cond_22

    .line 1069
    .line 1070
    if-ne v7, v14, :cond_22

    .line 1071
    .line 1072
    :goto_1b
    return v3

    .line 1073
    :cond_22
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->e()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 1074
    .line 1075
    .line 1076
    move-result-object v0

    .line 1077
    throw v0

    .line 1078
    nop

    .line 1079
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_a
        :pswitch_3
        :pswitch_8
        :pswitch_9
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final F(Ljava/lang/Object;[BIILcom/google/crypto/tink/shaded/protobuf/d;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v7, p2

    .line 4
    .line 5
    move/from16 v8, p4

    .line 6
    .line 7
    move-object/from16 v13, p5

    .line 8
    .line 9
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 10
    .line 11
    const/4 v14, -0x1

    .line 12
    const/4 v15, 0x0

    .line 13
    move/from16 v2, p3

    .line 14
    .line 15
    move v3, v14

    .line 16
    move v4, v15

    .line 17
    :goto_0
    if-ge v2, v8, :cond_18

    .line 18
    .line 19
    add-int/lit8 v5, v2, 0x1

    .line 20
    .line 21
    aget-byte v2, v7, v2

    .line 22
    .line 23
    if-gez v2, :cond_0

    .line 24
    .line 25
    invoke-static {v2, v7, v5, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->o(I[BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    iget v2, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 30
    .line 31
    :cond_0
    move v9, v5

    .line 32
    move v5, v2

    .line 33
    ushr-int/lit8 v10, v5, 0x3

    .line 34
    .line 35
    and-int/lit8 v6, v5, 0x7

    .line 36
    .line 37
    iget v2, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->d:I

    .line 38
    .line 39
    iget v11, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->c:I

    .line 40
    .line 41
    if-le v10, v3, :cond_2

    .line 42
    .line 43
    div-int/lit8 v4, v4, 0x3

    .line 44
    .line 45
    if-lt v10, v11, :cond_1

    .line 46
    .line 47
    if-gt v10, v2, :cond_1

    .line 48
    .line 49
    invoke-virtual {v0, v10, v4}, Lcom/google/crypto/tink/shaded/protobuf/r0;->M(II)I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    goto :goto_1

    .line 54
    :cond_1
    move v2, v14

    .line 55
    :goto_1
    move v12, v2

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    if-lt v10, v11, :cond_1

    .line 58
    .line 59
    if-gt v10, v2, :cond_1

    .line 60
    .line 61
    invoke-virtual {v0, v10, v15}, Lcom/google/crypto/tink/shaded/protobuf/r0;->M(II)I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    goto :goto_1

    .line 66
    :goto_2
    if-ne v12, v14, :cond_3

    .line 67
    .line 68
    move-object/from16 v16, v1

    .line 69
    .line 70
    move v2, v9

    .line 71
    move v11, v10

    .line 72
    move v12, v15

    .line 73
    goto/16 :goto_13

    .line 74
    .line 75
    :cond_3
    add-int/lit8 v2, v12, 0x1

    .line 76
    .line 77
    iget-object v3, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 78
    .line 79
    aget v2, v3, v2

    .line 80
    .line 81
    move v11, v10

    .line 82
    invoke-static {v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 83
    .line 84
    .line 85
    move-result v10

    .line 86
    const v3, 0xfffff

    .line 87
    .line 88
    .line 89
    and-int/2addr v3, v2

    .line 90
    int-to-long v3, v3

    .line 91
    const/16 v14, 0x11

    .line 92
    .line 93
    const/4 v15, 0x2

    .line 94
    if-gt v10, v14, :cond_d

    .line 95
    .line 96
    const/4 v14, 0x1

    .line 97
    packed-switch v10, :pswitch_data_0

    .line 98
    .line 99
    .line 100
    :cond_4
    move-object/from16 v16, v1

    .line 101
    .line 102
    move v3, v9

    .line 103
    move v14, v11

    .line 104
    move-object/from16 v1, p1

    .line 105
    .line 106
    goto/16 :goto_12

    .line 107
    .line 108
    :pswitch_0
    if-nez v6, :cond_4

    .line 109
    .line 110
    invoke-static {v7, v9, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 111
    .line 112
    .line 113
    move-result v9

    .line 114
    iget-wide v5, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 115
    .line 116
    invoke-static {v5, v6}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 117
    .line 118
    .line 119
    move-result-wide v5

    .line 120
    move-object/from16 v2, p1

    .line 121
    .line 122
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 123
    .line 124
    .line 125
    move-object v3, v1

    .line 126
    move-object v1, v2

    .line 127
    move-object v1, v3

    .line 128
    :goto_3
    move v2, v9

    .line 129
    :goto_4
    move v3, v11

    .line 130
    move v4, v12

    .line 131
    :goto_5
    const/4 v14, -0x1

    .line 132
    const/4 v15, 0x0

    .line 133
    goto :goto_0

    .line 134
    :pswitch_1
    move-wide v14, v3

    .line 135
    move-object v3, v1

    .line 136
    move-object/from16 v1, p1

    .line 137
    .line 138
    if-nez v6, :cond_5

    .line 139
    .line 140
    invoke-static {v7, v9, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 141
    .line 142
    .line 143
    move-result v2

    .line 144
    iget v4, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 145
    .line 146
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 147
    .line 148
    .line 149
    move-result v4

    .line 150
    invoke-virtual {v3, v1, v14, v15, v4}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 151
    .line 152
    .line 153
    :goto_6
    move-object v1, v3

    .line 154
    goto :goto_4

    .line 155
    :cond_5
    :goto_7
    move-object/from16 v16, v3

    .line 156
    .line 157
    :goto_8
    move v3, v9

    .line 158
    :goto_9
    move v14, v11

    .line 159
    goto/16 :goto_12

    .line 160
    .line 161
    :pswitch_2
    move-wide v14, v3

    .line 162
    move-object v3, v1

    .line 163
    move-object/from16 v1, p1

    .line 164
    .line 165
    if-nez v6, :cond_5

    .line 166
    .line 167
    invoke-static {v7, v9, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 168
    .line 169
    .line 170
    move-result v2

    .line 171
    iget v4, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 172
    .line 173
    invoke-virtual {v3, v1, v14, v15, v4}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 174
    .line 175
    .line 176
    goto :goto_6

    .line 177
    :pswitch_3
    move/from16 p3, v5

    .line 178
    .line 179
    move-wide v4, v3

    .line 180
    move-object v3, v1

    .line 181
    move-object/from16 v1, p1

    .line 182
    .line 183
    if-ne v6, v15, :cond_6

    .line 184
    .line 185
    invoke-static {v7, v9, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->e([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 186
    .line 187
    .line 188
    move-result v2

    .line 189
    iget-object v6, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 190
    .line 191
    invoke-virtual {v3, v1, v4, v5, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    goto :goto_6

    .line 195
    :cond_6
    :goto_a
    move/from16 v5, p3

    .line 196
    .line 197
    goto :goto_7

    .line 198
    :pswitch_4
    move/from16 p3, v5

    .line 199
    .line 200
    move-wide v4, v3

    .line 201
    move-object v3, v1

    .line 202
    move-object/from16 v1, p1

    .line 203
    .line 204
    if-ne v6, v15, :cond_6

    .line 205
    .line 206
    invoke-virtual {v0, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 207
    .line 208
    .line 209
    move-result-object v2

    .line 210
    invoke-static {v2, v7, v9, v8, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->i(Lcom/google/crypto/tink/shaded/protobuf/a1;[BIILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 211
    .line 212
    .line 213
    move-result v2

    .line 214
    invoke-virtual {v3, v1, v4, v5}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v6

    .line 218
    if-nez v6, :cond_7

    .line 219
    .line 220
    iget-object v6, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 221
    .line 222
    invoke-virtual {v3, v1, v4, v5, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    goto :goto_6

    .line 226
    :cond_7
    iget-object v9, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 227
    .line 228
    invoke-static {v6, v9}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 229
    .line 230
    .line 231
    move-result-object v6

    .line 232
    invoke-virtual {v3, v1, v4, v5, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    goto :goto_6

    .line 236
    :pswitch_5
    move/from16 p3, v5

    .line 237
    .line 238
    move-wide v4, v3

    .line 239
    move-object v3, v1

    .line 240
    move-object/from16 v1, p1

    .line 241
    .line 242
    if-ne v6, v15, :cond_6

    .line 243
    .line 244
    const/high16 v6, 0x20000000

    .line 245
    .line 246
    and-int/2addr v2, v6

    .line 247
    if-nez v2, :cond_8

    .line 248
    .line 249
    invoke-static {v7, v9, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->k([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 250
    .line 251
    .line 252
    move-result v2

    .line 253
    goto :goto_b

    .line 254
    :cond_8
    invoke-static {v7, v9, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->l([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 255
    .line 256
    .line 257
    move-result v2

    .line 258
    :goto_b
    iget-object v6, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 259
    .line 260
    invoke-virtual {v3, v1, v4, v5, v6}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    goto :goto_6

    .line 264
    :pswitch_6
    move/from16 p3, v5

    .line 265
    .line 266
    move-wide v4, v3

    .line 267
    move-object v3, v1

    .line 268
    move-object/from16 v1, p1

    .line 269
    .line 270
    if-nez v6, :cond_6

    .line 271
    .line 272
    invoke-static {v7, v9, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 273
    .line 274
    .line 275
    move-result v2

    .line 276
    iget-wide v9, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 277
    .line 278
    const-wide/16 v16, 0x0

    .line 279
    .line 280
    cmp-long v6, v9, v16

    .line 281
    .line 282
    if-eqz v6, :cond_9

    .line 283
    .line 284
    goto :goto_c

    .line 285
    :cond_9
    const/4 v14, 0x0

    .line 286
    :goto_c
    sget-object v6, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 287
    .line 288
    invoke-virtual {v6, v1, v4, v5, v14}, Lcom/google/crypto/tink/shaded/protobuf/k1;->k(Ljava/lang/Object;JZ)V

    .line 289
    .line 290
    .line 291
    goto/16 :goto_6

    .line 292
    .line 293
    :pswitch_7
    move/from16 p3, v5

    .line 294
    .line 295
    const/4 v2, 0x5

    .line 296
    move-wide v4, v3

    .line 297
    move-object v3, v1

    .line 298
    move-object/from16 v1, p1

    .line 299
    .line 300
    if-ne v6, v2, :cond_6

    .line 301
    .line 302
    invoke-static {v9, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 303
    .line 304
    .line 305
    move-result v2

    .line 306
    invoke-virtual {v3, v1, v4, v5, v2}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 307
    .line 308
    .line 309
    add-int/lit8 v2, v9, 0x4

    .line 310
    .line 311
    goto/16 :goto_6

    .line 312
    .line 313
    :pswitch_8
    move/from16 p3, v5

    .line 314
    .line 315
    move-wide v4, v3

    .line 316
    move-object v3, v1

    .line 317
    move-object/from16 v1, p1

    .line 318
    .line 319
    if-ne v6, v14, :cond_a

    .line 320
    .line 321
    move-wide v14, v4

    .line 322
    invoke-static {v9, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 323
    .line 324
    .line 325
    move-result-wide v5

    .line 326
    move-object v2, v1

    .line 327
    move-object v1, v3

    .line 328
    move-wide v3, v14

    .line 329
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 330
    .line 331
    .line 332
    add-int/lit8 v3, v9, 0x8

    .line 333
    .line 334
    move v2, v3

    .line 335
    goto/16 :goto_4

    .line 336
    .line 337
    :cond_a
    move-object v2, v1

    .line 338
    goto/16 :goto_a

    .line 339
    .line 340
    :pswitch_9
    move-object/from16 v2, p1

    .line 341
    .line 342
    move/from16 p3, v5

    .line 343
    .line 344
    if-nez v6, :cond_b

    .line 345
    .line 346
    invoke-static {v7, v9, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 347
    .line 348
    .line 349
    move-result v5

    .line 350
    iget v6, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 351
    .line 352
    invoke-virtual {v1, v2, v3, v4, v6}, Lsun/misc/Unsafe;->putInt(Ljava/lang/Object;JI)V

    .line 353
    .line 354
    .line 355
    move v2, v5

    .line 356
    goto/16 :goto_4

    .line 357
    .line 358
    :cond_b
    move/from16 v5, p3

    .line 359
    .line 360
    move-object/from16 v16, v1

    .line 361
    .line 362
    move-object v1, v2

    .line 363
    goto/16 :goto_8

    .line 364
    .line 365
    :pswitch_a
    move-object/from16 v2, p1

    .line 366
    .line 367
    move/from16 p3, v5

    .line 368
    .line 369
    if-nez v6, :cond_b

    .line 370
    .line 371
    invoke-static {v7, v9, v13}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 372
    .line 373
    .line 374
    move-result v9

    .line 375
    iget-wide v5, v13, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 376
    .line 377
    invoke-virtual/range {v1 .. v6}, Lsun/misc/Unsafe;->putLong(Ljava/lang/Object;JJ)V

    .line 378
    .line 379
    .line 380
    goto/16 :goto_3

    .line 381
    .line 382
    :pswitch_b
    move-object/from16 v2, p1

    .line 383
    .line 384
    move-object v10, v1

    .line 385
    move/from16 p3, v5

    .line 386
    .line 387
    const/4 v1, 0x5

    .line 388
    if-ne v6, v1, :cond_c

    .line 389
    .line 390
    invoke-static {v9, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 391
    .line 392
    .line 393
    move-result v1

    .line 394
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 395
    .line 396
    .line 397
    move-result v1

    .line 398
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 399
    .line 400
    invoke-virtual {v5, v2, v3, v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->n(Ljava/lang/Object;JF)V

    .line 401
    .line 402
    .line 403
    add-int/lit8 v1, v9, 0x4

    .line 404
    .line 405
    move v2, v1

    .line 406
    :goto_d
    move-object v1, v10

    .line 407
    goto/16 :goto_4

    .line 408
    .line 409
    :cond_c
    move/from16 v5, p3

    .line 410
    .line 411
    move-object v1, v2

    .line 412
    move v3, v9

    .line 413
    move-object/from16 v16, v10

    .line 414
    .line 415
    goto/16 :goto_9

    .line 416
    .line 417
    :pswitch_c
    move-object/from16 v2, p1

    .line 418
    .line 419
    move-object v10, v1

    .line 420
    move/from16 p3, v5

    .line 421
    .line 422
    if-ne v6, v14, :cond_c

    .line 423
    .line 424
    invoke-static {v9, v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 425
    .line 426
    .line 427
    move-result-wide v5

    .line 428
    invoke-static {v5, v6}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 429
    .line 430
    .line 431
    move-result-wide v5

    .line 432
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 433
    .line 434
    invoke-virtual/range {v1 .. v6}, Lcom/google/crypto/tink/shaded/protobuf/k1;->m(Ljava/lang/Object;JD)V

    .line 435
    .line 436
    .line 437
    move-object v14, v2

    .line 438
    add-int/lit8 v2, v9, 0x8

    .line 439
    .line 440
    goto :goto_d

    .line 441
    :cond_d
    move-object/from16 v14, p1

    .line 442
    .line 443
    move/from16 p3, v5

    .line 444
    .line 445
    const/16 v5, 0x1b

    .line 446
    .line 447
    if-ne v10, v5, :cond_11

    .line 448
    .line 449
    if-ne v6, v15, :cond_10

    .line 450
    .line 451
    invoke-virtual {v1, v14, v3, v4}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    move-result-object v2

    .line 455
    check-cast v2, Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 456
    .line 457
    move-object v5, v2

    .line 458
    check-cast v5, Lcom/google/crypto/tink/shaded/protobuf/b;

    .line 459
    .line 460
    iget-boolean v5, v5, Lcom/google/crypto/tink/shaded/protobuf/b;->d:Z

    .line 461
    .line 462
    if-nez v5, :cond_f

    .line 463
    .line 464
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 465
    .line 466
    .line 467
    move-result v5

    .line 468
    if-nez v5, :cond_e

    .line 469
    .line 470
    const/16 v5, 0xa

    .line 471
    .line 472
    goto :goto_e

    .line 473
    :cond_e
    mul-int/lit8 v5, v5, 0x2

    .line 474
    .line 475
    :goto_e
    invoke-interface {v2, v5}, Lcom/google/crypto/tink/shaded/protobuf/a0;->a(I)Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 476
    .line 477
    .line 478
    move-result-object v2

    .line 479
    invoke-virtual {v1, v14, v3, v4, v2}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 480
    .line 481
    .line 482
    :cond_f
    move-object v10, v1

    .line 483
    move-object v6, v2

    .line 484
    invoke-virtual {v0, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 485
    .line 486
    .line 487
    move-result-object v1

    .line 488
    move/from16 v2, p3

    .line 489
    .line 490
    move-object v3, v7

    .line 491
    move v5, v8

    .line 492
    move v4, v9

    .line 493
    move-object/from16 v16, v10

    .line 494
    .line 495
    move-object v7, v13

    .line 496
    invoke-static/range {v1 .. v7}, Lcom/google/crypto/tink/shaded/protobuf/q0;->j(Lcom/google/crypto/tink/shaded/protobuf/a1;I[BIILcom/google/crypto/tink/shaded/protobuf/a0;Lcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 497
    .line 498
    .line 499
    move-result v2

    .line 500
    move-object/from16 v7, p2

    .line 501
    .line 502
    move/from16 v8, p4

    .line 503
    .line 504
    move-object/from16 v13, p5

    .line 505
    .line 506
    :goto_f
    move v3, v11

    .line 507
    move v4, v12

    .line 508
    :goto_10
    move-object/from16 v1, v16

    .line 509
    .line 510
    goto/16 :goto_5

    .line 511
    .line 512
    :cond_10
    move-object/from16 v16, v1

    .line 513
    .line 514
    move/from16 v5, p3

    .line 515
    .line 516
    move v3, v9

    .line 517
    move-object v1, v14

    .line 518
    goto/16 :goto_9

    .line 519
    .line 520
    :cond_11
    move/from16 v5, p3

    .line 521
    .line 522
    move-object/from16 v16, v1

    .line 523
    .line 524
    move v1, v9

    .line 525
    const/16 v7, 0x31

    .line 526
    .line 527
    if-gt v10, v7, :cond_13

    .line 528
    .line 529
    int-to-long v8, v2

    .line 530
    move-object/from16 v2, p2

    .line 531
    .line 532
    move-object/from16 v13, p5

    .line 533
    .line 534
    move v7, v12

    .line 535
    move-wide/from16 v18, v3

    .line 536
    .line 537
    move/from16 v4, p4

    .line 538
    .line 539
    move v3, v1

    .line 540
    move-object v1, v14

    .line 541
    move v14, v11

    .line 542
    move-wide/from16 v11, v18

    .line 543
    .line 544
    invoke-virtual/range {v0 .. v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->G(Ljava/lang/Object;[BIIIIIJIJLcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 545
    .line 546
    .line 547
    move-result v6

    .line 548
    move v12, v7

    .line 549
    if-eq v6, v3, :cond_12

    .line 550
    .line 551
    move-object/from16 v7, p2

    .line 552
    .line 553
    move/from16 v8, p4

    .line 554
    .line 555
    move-object/from16 v13, p5

    .line 556
    .line 557
    move v2, v6

    .line 558
    move v4, v12

    .line 559
    move v3, v14

    .line 560
    goto :goto_10

    .line 561
    :cond_12
    move v2, v6

    .line 562
    :goto_11
    move v11, v14

    .line 563
    goto :goto_13

    .line 564
    :cond_13
    move-wide v7, v3

    .line 565
    move v3, v1

    .line 566
    move-object v1, v14

    .line 567
    move v14, v11

    .line 568
    const/16 v4, 0x32

    .line 569
    .line 570
    if-ne v10, v4, :cond_15

    .line 571
    .line 572
    if-eq v6, v15, :cond_14

    .line 573
    .line 574
    :goto_12
    move v2, v3

    .line 575
    goto :goto_11

    .line 576
    :cond_14
    invoke-virtual {v0, v7, v8, v1, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->C(JLjava/lang/Object;I)V

    .line 577
    .line 578
    .line 579
    const/4 v0, 0x0

    .line 580
    throw v0

    .line 581
    :cond_15
    move/from16 v4, p4

    .line 582
    .line 583
    move-object/from16 v13, p5

    .line 584
    .line 585
    move v9, v10

    .line 586
    move-wide v10, v7

    .line 587
    move v8, v2

    .line 588
    move v7, v6

    .line 589
    move v6, v14

    .line 590
    move-object/from16 v2, p2

    .line 591
    .line 592
    invoke-virtual/range {v0 .. v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->D(Ljava/lang/Object;[BIIIIIIIJILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 593
    .line 594
    .line 595
    move-result v7

    .line 596
    move v11, v6

    .line 597
    if-eq v7, v3, :cond_16

    .line 598
    .line 599
    move-object/from16 v0, p0

    .line 600
    .line 601
    move/from16 v8, p4

    .line 602
    .line 603
    move-object/from16 v13, p5

    .line 604
    .line 605
    move v2, v7

    .line 606
    move v3, v11

    .line 607
    move v4, v12

    .line 608
    move-object/from16 v1, v16

    .line 609
    .line 610
    const/4 v14, -0x1

    .line 611
    const/4 v15, 0x0

    .line 612
    move-object/from16 v7, p2

    .line 613
    .line 614
    goto/16 :goto_0

    .line 615
    .line 616
    :cond_16
    move v2, v7

    .line 617
    :goto_13
    move-object/from16 v0, p1

    .line 618
    .line 619
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 620
    .line 621
    iget-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 622
    .line 623
    sget-object v3, Lcom/google/crypto/tink/shaded/protobuf/c1;->f:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 624
    .line 625
    if-ne v1, v3, :cond_17

    .line 626
    .line 627
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c1;->b()Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 628
    .line 629
    .line 630
    move-result-object v1

    .line 631
    iput-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 632
    .line 633
    :cond_17
    move/from16 v3, p4

    .line 634
    .line 635
    move-object v4, v1

    .line 636
    move v0, v5

    .line 637
    move-object/from16 v1, p2

    .line 638
    .line 639
    move-object/from16 v5, p5

    .line 640
    .line 641
    invoke-static/range {v0 .. v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->m(I[BIILcom/google/crypto/tink/shaded/protobuf/c1;Lcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 642
    .line 643
    .line 644
    move-result v2

    .line 645
    move-object/from16 v0, p0

    .line 646
    .line 647
    move-object/from16 v7, p2

    .line 648
    .line 649
    move-object/from16 v13, p5

    .line 650
    .line 651
    move v8, v3

    .line 652
    goto/16 :goto_f

    .line 653
    .line 654
    :cond_18
    move v4, v8

    .line 655
    if-ne v2, v4, :cond_19

    .line 656
    .line 657
    return-void

    .line 658
    :cond_19
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->e()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 659
    .line 660
    .line 661
    move-result-object v0

    .line 662
    throw v0

    .line 663
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_9
        :pswitch_2
        :pswitch_7
        :pswitch_8
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final G(Ljava/lang/Object;[BIIIIIJIJLcom/google/crypto/tink/shaded/protobuf/d;)I
    .locals 11

    .line 1
    move/from16 v0, p5

    .line 2
    .line 3
    move/from16 v1, p6

    .line 4
    .line 5
    move/from16 v6, p7

    .line 6
    .line 7
    move-wide/from16 v2, p11

    .line 8
    .line 9
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 10
    .line 11
    invoke-virtual {v4, p1, v2, v3}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v5

    .line 15
    check-cast v5, Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 16
    .line 17
    move-object v7, v5

    .line 18
    check-cast v7, Lcom/google/crypto/tink/shaded/protobuf/b;

    .line 19
    .line 20
    iget-boolean v7, v7, Lcom/google/crypto/tink/shaded/protobuf/b;->d:Z

    .line 21
    .line 22
    const/4 v8, 0x2

    .line 23
    if-nez v7, :cond_1

    .line 24
    .line 25
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 26
    .line 27
    .line 28
    move-result v7

    .line 29
    if-nez v7, :cond_0

    .line 30
    .line 31
    const/16 v7, 0xa

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    mul-int/2addr v7, v8

    .line 35
    :goto_0
    invoke-interface {v5, v7}, Lcom/google/crypto/tink/shaded/protobuf/a0;->a(I)Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    invoke-virtual {v4, p1, v2, v3, v5}, Lsun/misc/Unsafe;->putObject(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    :cond_1
    move-object v4, v5

    .line 43
    const/4 v2, 0x5

    .line 44
    const-wide/16 v9, 0x0

    .line 45
    .line 46
    const/4 v3, 0x1

    .line 47
    packed-switch p10, :pswitch_data_0

    .line 48
    .line 49
    .line 50
    goto/16 :goto_2a

    .line 51
    .line 52
    :pswitch_0
    const/4 p1, 0x3

    .line 53
    if-ne v1, p1, :cond_4e

    .line 54
    .line 55
    invoke-virtual {p0, v6}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    and-int/lit8 p1, v0, -0x8

    .line 60
    .line 61
    or-int/lit8 p1, p1, 0x4

    .line 62
    .line 63
    move-object/from16 p6, p0

    .line 64
    .line 65
    move/from16 p10, p1

    .line 66
    .line 67
    move-object/from16 p7, p2

    .line 68
    .line 69
    move/from16 p8, p3

    .line 70
    .line 71
    move/from16 p9, p4

    .line 72
    .line 73
    move-object/from16 p11, p13

    .line 74
    .line 75
    invoke-static/range {p6 .. p11}, Lcom/google/crypto/tink/shaded/protobuf/q0;->h(Lcom/google/crypto/tink/shaded/protobuf/a1;[BIIILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    move-object/from16 p1, p6

    .line 80
    .line 81
    move/from16 v3, p9

    .line 82
    .line 83
    move/from16 v2, p10

    .line 84
    .line 85
    move-object/from16 v5, p11

    .line 86
    .line 87
    iget-object v6, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 88
    .line 89
    invoke-interface {v4, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    :goto_1
    if-ge p0, v3, :cond_3

    .line 93
    .line 94
    invoke-static {p2, p0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 95
    .line 96
    .line 97
    move-result v6

    .line 98
    iget v7, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 99
    .line 100
    if-eq v0, v7, :cond_2

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_2
    move-object/from16 p6, p1

    .line 104
    .line 105
    move-object/from16 p7, p2

    .line 106
    .line 107
    move/from16 p10, v2

    .line 108
    .line 109
    move/from16 p9, v3

    .line 110
    .line 111
    move-object/from16 p11, v5

    .line 112
    .line 113
    move/from16 p8, v6

    .line 114
    .line 115
    invoke-static/range {p6 .. p11}, Lcom/google/crypto/tink/shaded/protobuf/q0;->h(Lcom/google/crypto/tink/shaded/protobuf/a1;[BIIILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    move/from16 v1, p10

    .line 120
    .line 121
    iget-object v6, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 122
    .line 123
    invoke-interface {v4, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move v2, v1

    .line 127
    goto :goto_1

    .line 128
    :cond_3
    :goto_2
    return p0

    .line 129
    :pswitch_1
    move v3, p4

    .line 130
    move-object/from16 v5, p13

    .line 131
    .line 132
    if-ne v1, v8, :cond_6

    .line 133
    .line 134
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 135
    .line 136
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 137
    .line 138
    .line 139
    move-result p0

    .line 140
    iget p1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 141
    .line 142
    add-int/2addr p1, p0

    .line 143
    :goto_3
    if-ge p0, p1, :cond_4

    .line 144
    .line 145
    invoke-static {p2, p0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 146
    .line 147
    .line 148
    move-result p0

    .line 149
    iget-wide v0, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 150
    .line 151
    invoke-static {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 152
    .line 153
    .line 154
    move-result-wide v0

    .line 155
    invoke-virtual {v4, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 156
    .line 157
    .line 158
    goto :goto_3

    .line 159
    :cond_4
    if-ne p0, p1, :cond_5

    .line 160
    .line 161
    return p0

    .line 162
    :cond_5
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    throw p0

    .line 167
    :cond_6
    if-nez v1, :cond_4e

    .line 168
    .line 169
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 170
    .line 171
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 172
    .line 173
    .line 174
    move-result p0

    .line 175
    iget-wide v6, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 176
    .line 177
    invoke-static {v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 178
    .line 179
    .line 180
    move-result-wide v6

    .line 181
    invoke-virtual {v4, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 182
    .line 183
    .line 184
    :goto_4
    if-ge p0, v3, :cond_8

    .line 185
    .line 186
    invoke-static {p2, p0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 187
    .line 188
    .line 189
    move-result p1

    .line 190
    iget v1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 191
    .line 192
    if-eq v0, v1, :cond_7

    .line 193
    .line 194
    goto :goto_5

    .line 195
    :cond_7
    invoke-static {p2, p1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 196
    .line 197
    .line 198
    move-result p0

    .line 199
    iget-wide v6, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 200
    .line 201
    invoke-static {v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/j;->b(J)J

    .line 202
    .line 203
    .line 204
    move-result-wide v6

    .line 205
    invoke-virtual {v4, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 206
    .line 207
    .line 208
    goto :goto_4

    .line 209
    :cond_8
    :goto_5
    return p0

    .line 210
    :pswitch_2
    move v3, p4

    .line 211
    move-object/from16 v5, p13

    .line 212
    .line 213
    if-ne v1, v8, :cond_b

    .line 214
    .line 215
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 216
    .line 217
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 218
    .line 219
    .line 220
    move-result p0

    .line 221
    iget p1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 222
    .line 223
    add-int/2addr p1, p0

    .line 224
    :goto_6
    if-ge p0, p1, :cond_9

    .line 225
    .line 226
    invoke-static {p2, p0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 227
    .line 228
    .line 229
    move-result p0

    .line 230
    iget v0, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 231
    .line 232
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 233
    .line 234
    .line 235
    move-result v0

    .line 236
    invoke-virtual {v4, v0}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 237
    .line 238
    .line 239
    goto :goto_6

    .line 240
    :cond_9
    if-ne p0, p1, :cond_a

    .line 241
    .line 242
    return p0

    .line 243
    :cond_a
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 244
    .line 245
    .line 246
    move-result-object p0

    .line 247
    throw p0

    .line 248
    :cond_b
    if-nez v1, :cond_4e

    .line 249
    .line 250
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 251
    .line 252
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 253
    .line 254
    .line 255
    move-result p0

    .line 256
    iget p1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 257
    .line 258
    invoke-static {p1}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 259
    .line 260
    .line 261
    move-result p1

    .line 262
    invoke-virtual {v4, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 263
    .line 264
    .line 265
    :goto_7
    if-ge p0, v3, :cond_d

    .line 266
    .line 267
    invoke-static {p2, p0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 268
    .line 269
    .line 270
    move-result p1

    .line 271
    iget v1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 272
    .line 273
    if-eq v0, v1, :cond_c

    .line 274
    .line 275
    goto :goto_8

    .line 276
    :cond_c
    invoke-static {p2, p1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 277
    .line 278
    .line 279
    move-result p0

    .line 280
    iget p1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 281
    .line 282
    invoke-static {p1}, Lcom/google/crypto/tink/shaded/protobuf/j;->a(I)I

    .line 283
    .line 284
    .line 285
    move-result p1

    .line 286
    invoke-virtual {v4, p1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 287
    .line 288
    .line 289
    goto :goto_7

    .line 290
    :cond_d
    :goto_8
    return p0

    .line 291
    :pswitch_3
    move v3, p4

    .line 292
    move-object/from16 v5, p13

    .line 293
    .line 294
    if-ne v1, v8, :cond_10

    .line 295
    .line 296
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 297
    .line 298
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 299
    .line 300
    .line 301
    move-result v0

    .line 302
    iget v1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 303
    .line 304
    add-int/2addr v1, v0

    .line 305
    :goto_9
    if-ge v0, v1, :cond_e

    .line 306
    .line 307
    invoke-static {p2, v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 308
    .line 309
    .line 310
    move-result v0

    .line 311
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 312
    .line 313
    invoke-virtual {v4, v3}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 314
    .line 315
    .line 316
    goto :goto_9

    .line 317
    :cond_e
    if-ne v0, v1, :cond_f

    .line 318
    .line 319
    goto :goto_a

    .line 320
    :cond_f
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 321
    .line 322
    .line 323
    move-result-object p0

    .line 324
    throw p0

    .line 325
    :cond_10
    if-nez v1, :cond_4e

    .line 326
    .line 327
    move-object v1, p2

    .line 328
    move v2, p3

    .line 329
    invoke-static/range {v0 .. v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->q(I[BIILcom/google/crypto/tink/shaded/protobuf/a0;Lcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 330
    .line 331
    .line 332
    move-result v0

    .line 333
    :goto_a
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 334
    .line 335
    iget-object v1, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 336
    .line 337
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/c1;->f:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 338
    .line 339
    if-ne v1, v2, :cond_11

    .line 340
    .line 341
    const/4 v1, 0x0

    .line 342
    :cond_11
    invoke-virtual {p0, v6}, Lcom/google/crypto/tink/shaded/protobuf/r0;->m(I)V

    .line 343
    .line 344
    .line 345
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 346
    .line 347
    if-eqz v1, :cond_12

    .line 348
    .line 349
    iput-object v1, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 350
    .line 351
    :cond_12
    return v0

    .line 352
    :pswitch_4
    move v3, p4

    .line 353
    move-object/from16 v5, p13

    .line 354
    .line 355
    if-ne v1, v8, :cond_4e

    .line 356
    .line 357
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 358
    .line 359
    .line 360
    move-result p0

    .line 361
    iget v1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 362
    .line 363
    if-ltz v1, :cond_1a

    .line 364
    .line 365
    array-length v2, p2

    .line 366
    sub-int/2addr v2, p0

    .line 367
    if-gt v1, v2, :cond_19

    .line 368
    .line 369
    if-nez v1, :cond_13

    .line 370
    .line 371
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/i;->e:Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 372
    .line 373
    invoke-interface {v4, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 374
    .line 375
    .line 376
    goto :goto_c

    .line 377
    :cond_13
    invoke-static {p2, p0, v1}, Lcom/google/crypto/tink/shaded/protobuf/i;->g([BII)Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 378
    .line 379
    .line 380
    move-result-object v2

    .line 381
    invoke-interface {v4, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 382
    .line 383
    .line 384
    :goto_b
    add-int/2addr p0, v1

    .line 385
    :goto_c
    if-ge p0, v3, :cond_18

    .line 386
    .line 387
    invoke-static {p2, p0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 388
    .line 389
    .line 390
    move-result v1

    .line 391
    iget v2, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 392
    .line 393
    if-eq v0, v2, :cond_14

    .line 394
    .line 395
    goto :goto_d

    .line 396
    :cond_14
    invoke-static {p2, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 397
    .line 398
    .line 399
    move-result p0

    .line 400
    iget v1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 401
    .line 402
    if-ltz v1, :cond_17

    .line 403
    .line 404
    array-length v2, p2

    .line 405
    sub-int/2addr v2, p0

    .line 406
    if-gt v1, v2, :cond_16

    .line 407
    .line 408
    if-nez v1, :cond_15

    .line 409
    .line 410
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/i;->e:Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 411
    .line 412
    invoke-interface {v4, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 413
    .line 414
    .line 415
    goto :goto_c

    .line 416
    :cond_15
    invoke-static {p2, p0, v1}, Lcom/google/crypto/tink/shaded/protobuf/i;->g([BII)Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 417
    .line 418
    .line 419
    move-result-object v2

    .line 420
    invoke-interface {v4, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 421
    .line 422
    .line 423
    goto :goto_b

    .line 424
    :cond_16
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 425
    .line 426
    .line 427
    move-result-object p0

    .line 428
    throw p0

    .line 429
    :cond_17
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->d()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 430
    .line 431
    .line 432
    move-result-object p0

    .line 433
    throw p0

    .line 434
    :cond_18
    :goto_d
    return p0

    .line 435
    :cond_19
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 436
    .line 437
    .line 438
    move-result-object p0

    .line 439
    throw p0

    .line 440
    :cond_1a
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->d()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 441
    .line 442
    .line 443
    move-result-object p0

    .line 444
    throw p0

    .line 445
    :pswitch_5
    move v3, p4

    .line 446
    move-object/from16 v5, p13

    .line 447
    .line 448
    if-ne v1, v8, :cond_4e

    .line 449
    .line 450
    invoke-virtual {p0, v6}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 451
    .line 452
    .line 453
    move-result-object p0

    .line 454
    move-object/from16 p6, p0

    .line 455
    .line 456
    move-object/from16 p8, p2

    .line 457
    .line 458
    move/from16 p9, p3

    .line 459
    .line 460
    move/from16 p7, v0

    .line 461
    .line 462
    move/from16 p10, v3

    .line 463
    .line 464
    move-object/from16 p11, v4

    .line 465
    .line 466
    move-object/from16 p12, v5

    .line 467
    .line 468
    invoke-static/range {p6 .. p12}, Lcom/google/crypto/tink/shaded/protobuf/q0;->j(Lcom/google/crypto/tink/shaded/protobuf/a1;I[BIILcom/google/crypto/tink/shaded/protobuf/a0;Lcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 469
    .line 470
    .line 471
    move-result p0

    .line 472
    return p0

    .line 473
    :pswitch_6
    move p0, p4

    .line 474
    move-object/from16 v5, p13

    .line 475
    .line 476
    if-ne v1, v8, :cond_4e

    .line 477
    .line 478
    const-wide/32 v1, 0x20000000

    .line 479
    .line 480
    .line 481
    and-long v1, p8, v1

    .line 482
    .line 483
    cmp-long v1, v1, v9

    .line 484
    .line 485
    const-string v2, ""

    .line 486
    .line 487
    if-nez v1, :cond_21

    .line 488
    .line 489
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 490
    .line 491
    .line 492
    move-result v1

    .line 493
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 494
    .line 495
    if-ltz v3, :cond_20

    .line 496
    .line 497
    if-nez v3, :cond_1b

    .line 498
    .line 499
    invoke-interface {v4, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 500
    .line 501
    .line 502
    goto :goto_f

    .line 503
    :cond_1b
    new-instance v6, Ljava/lang/String;

    .line 504
    .line 505
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 506
    .line 507
    invoke-direct {v6, p2, v1, v3, v7}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 508
    .line 509
    .line 510
    invoke-interface {v4, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 511
    .line 512
    .line 513
    :goto_e
    add-int/2addr v1, v3

    .line 514
    :goto_f
    if-ge v1, p0, :cond_1f

    .line 515
    .line 516
    invoke-static {p2, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 517
    .line 518
    .line 519
    move-result v3

    .line 520
    iget v6, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 521
    .line 522
    if-eq v0, v6, :cond_1c

    .line 523
    .line 524
    goto :goto_10

    .line 525
    :cond_1c
    invoke-static {p2, v3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 526
    .line 527
    .line 528
    move-result v1

    .line 529
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 530
    .line 531
    if-ltz v3, :cond_1e

    .line 532
    .line 533
    if-nez v3, :cond_1d

    .line 534
    .line 535
    invoke-interface {v4, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 536
    .line 537
    .line 538
    goto :goto_f

    .line 539
    :cond_1d
    new-instance v6, Ljava/lang/String;

    .line 540
    .line 541
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 542
    .line 543
    invoke-direct {v6, p2, v1, v3, v7}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 544
    .line 545
    .line 546
    invoke-interface {v4, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 547
    .line 548
    .line 549
    goto :goto_e

    .line 550
    :cond_1e
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->d()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 551
    .line 552
    .line 553
    move-result-object p0

    .line 554
    throw p0

    .line 555
    :cond_1f
    :goto_10
    return v1

    .line 556
    :cond_20
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->d()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 557
    .line 558
    .line 559
    move-result-object p0

    .line 560
    throw p0

    .line 561
    :cond_21
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 562
    .line 563
    .line 564
    move-result v1

    .line 565
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 566
    .line 567
    if-ltz v3, :cond_29

    .line 568
    .line 569
    if-nez v3, :cond_22

    .line 570
    .line 571
    invoke-interface {v4, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 572
    .line 573
    .line 574
    goto :goto_12

    .line 575
    :cond_22
    add-int v6, v1, v3

    .line 576
    .line 577
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/o1;->a:Lcom/google/crypto/tink/shaded/protobuf/q0;

    .line 578
    .line 579
    invoke-virtual {v7, p2, v1, v6}, Lcom/google/crypto/tink/shaded/protobuf/q0;->v([BII)Z

    .line 580
    .line 581
    .line 582
    move-result v7

    .line 583
    if-eqz v7, :cond_28

    .line 584
    .line 585
    new-instance v7, Ljava/lang/String;

    .line 586
    .line 587
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 588
    .line 589
    invoke-direct {v7, p2, v1, v3, v8}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 590
    .line 591
    .line 592
    invoke-interface {v4, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 593
    .line 594
    .line 595
    :goto_11
    move v1, v6

    .line 596
    :goto_12
    if-ge v1, p0, :cond_27

    .line 597
    .line 598
    invoke-static {p2, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 599
    .line 600
    .line 601
    move-result v3

    .line 602
    iget v6, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 603
    .line 604
    if-eq v0, v6, :cond_23

    .line 605
    .line 606
    goto :goto_13

    .line 607
    :cond_23
    invoke-static {p2, v3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 608
    .line 609
    .line 610
    move-result v1

    .line 611
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 612
    .line 613
    if-ltz v3, :cond_26

    .line 614
    .line 615
    if-nez v3, :cond_24

    .line 616
    .line 617
    invoke-interface {v4, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 618
    .line 619
    .line 620
    goto :goto_12

    .line 621
    :cond_24
    add-int v6, v1, v3

    .line 622
    .line 623
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/o1;->a:Lcom/google/crypto/tink/shaded/protobuf/q0;

    .line 624
    .line 625
    invoke-virtual {v7, p2, v1, v6}, Lcom/google/crypto/tink/shaded/protobuf/q0;->v([BII)Z

    .line 626
    .line 627
    .line 628
    move-result v7

    .line 629
    if-eqz v7, :cond_25

    .line 630
    .line 631
    new-instance v7, Ljava/lang/String;

    .line 632
    .line 633
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 634
    .line 635
    invoke-direct {v7, p2, v1, v3, v8}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 636
    .line 637
    .line 638
    invoke-interface {v4, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 639
    .line 640
    .line 641
    goto :goto_11

    .line 642
    :cond_25
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->a()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 643
    .line 644
    .line 645
    move-result-object p0

    .line 646
    throw p0

    .line 647
    :cond_26
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->d()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 648
    .line 649
    .line 650
    move-result-object p0

    .line 651
    throw p0

    .line 652
    :cond_27
    :goto_13
    return v1

    .line 653
    :cond_28
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->a()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 654
    .line 655
    .line 656
    move-result-object p0

    .line 657
    throw p0

    .line 658
    :cond_29
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->d()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 659
    .line 660
    .line 661
    move-result-object p0

    .line 662
    throw p0

    .line 663
    :pswitch_7
    move p0, p4

    .line 664
    move-object/from16 v5, p13

    .line 665
    .line 666
    const/4 v2, 0x0

    .line 667
    if-ne v1, v8, :cond_2d

    .line 668
    .line 669
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/e;

    .line 670
    .line 671
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 672
    .line 673
    .line 674
    move-result p0

    .line 675
    iget v0, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 676
    .line 677
    add-int/2addr v0, p0

    .line 678
    :goto_14
    if-ge p0, v0, :cond_2b

    .line 679
    .line 680
    invoke-static {p2, p0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 681
    .line 682
    .line 683
    move-result p0

    .line 684
    iget-wide v6, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 685
    .line 686
    cmp-long v1, v6, v9

    .line 687
    .line 688
    if-eqz v1, :cond_2a

    .line 689
    .line 690
    move v1, v3

    .line 691
    goto :goto_15

    .line 692
    :cond_2a
    move v1, v2

    .line 693
    :goto_15
    invoke-virtual {v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/e;->e(Z)V

    .line 694
    .line 695
    .line 696
    goto :goto_14

    .line 697
    :cond_2b
    if-ne p0, v0, :cond_2c

    .line 698
    .line 699
    return p0

    .line 700
    :cond_2c
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 701
    .line 702
    .line 703
    move-result-object p0

    .line 704
    throw p0

    .line 705
    :cond_2d
    if-nez v1, :cond_4e

    .line 706
    .line 707
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/e;

    .line 708
    .line 709
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 710
    .line 711
    .line 712
    move-result v1

    .line 713
    iget-wide v6, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 714
    .line 715
    cmp-long v6, v6, v9

    .line 716
    .line 717
    if-eqz v6, :cond_2e

    .line 718
    .line 719
    move v6, v3

    .line 720
    goto :goto_16

    .line 721
    :cond_2e
    move v6, v2

    .line 722
    :goto_16
    invoke-virtual {v4, v6}, Lcom/google/crypto/tink/shaded/protobuf/e;->e(Z)V

    .line 723
    .line 724
    .line 725
    :goto_17
    if-ge v1, p0, :cond_31

    .line 726
    .line 727
    invoke-static {p2, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 728
    .line 729
    .line 730
    move-result v6

    .line 731
    iget v7, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 732
    .line 733
    if-eq v0, v7, :cond_2f

    .line 734
    .line 735
    goto :goto_19

    .line 736
    :cond_2f
    invoke-static {p2, v6, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 737
    .line 738
    .line 739
    move-result v1

    .line 740
    iget-wide v6, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 741
    .line 742
    cmp-long v6, v6, v9

    .line 743
    .line 744
    if-eqz v6, :cond_30

    .line 745
    .line 746
    move v6, v3

    .line 747
    goto :goto_18

    .line 748
    :cond_30
    move v6, v2

    .line 749
    :goto_18
    invoke-virtual {v4, v6}, Lcom/google/crypto/tink/shaded/protobuf/e;->e(Z)V

    .line 750
    .line 751
    .line 752
    goto :goto_17

    .line 753
    :cond_31
    :goto_19
    return v1

    .line 754
    :pswitch_8
    move p0, p4

    .line 755
    move-object/from16 v5, p13

    .line 756
    .line 757
    if-ne v1, v8, :cond_34

    .line 758
    .line 759
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 760
    .line 761
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 762
    .line 763
    .line 764
    move-result p0

    .line 765
    iget v0, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 766
    .line 767
    add-int/2addr v0, p0

    .line 768
    :goto_1a
    if-ge p0, v0, :cond_32

    .line 769
    .line 770
    invoke-static {p0, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 771
    .line 772
    .line 773
    move-result v1

    .line 774
    invoke-virtual {v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 775
    .line 776
    .line 777
    add-int/lit8 p0, p0, 0x4

    .line 778
    .line 779
    goto :goto_1a

    .line 780
    :cond_32
    if-ne p0, v0, :cond_33

    .line 781
    .line 782
    return p0

    .line 783
    :cond_33
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 784
    .line 785
    .line 786
    move-result-object p0

    .line 787
    throw p0

    .line 788
    :cond_34
    if-ne v1, v2, :cond_4e

    .line 789
    .line 790
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 791
    .line 792
    invoke-static {p3, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 793
    .line 794
    .line 795
    move-result v1

    .line 796
    invoke-virtual {v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 797
    .line 798
    .line 799
    add-int/lit8 v1, p3, 0x4

    .line 800
    .line 801
    :goto_1b
    if-ge v1, p0, :cond_36

    .line 802
    .line 803
    invoke-static {p2, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 804
    .line 805
    .line 806
    move-result v2

    .line 807
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 808
    .line 809
    if-eq v0, v3, :cond_35

    .line 810
    .line 811
    goto :goto_1c

    .line 812
    :cond_35
    invoke-static {v2, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 813
    .line 814
    .line 815
    move-result v1

    .line 816
    invoke-virtual {v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 817
    .line 818
    .line 819
    add-int/lit8 v1, v2, 0x4

    .line 820
    .line 821
    goto :goto_1b

    .line 822
    :cond_36
    :goto_1c
    return v1

    .line 823
    :pswitch_9
    move p0, p4

    .line 824
    move-object/from16 v5, p13

    .line 825
    .line 826
    if-ne v1, v8, :cond_39

    .line 827
    .line 828
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 829
    .line 830
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 831
    .line 832
    .line 833
    move-result p0

    .line 834
    iget v0, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 835
    .line 836
    add-int/2addr v0, p0

    .line 837
    :goto_1d
    if-ge p0, v0, :cond_37

    .line 838
    .line 839
    invoke-static {p0, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 840
    .line 841
    .line 842
    move-result-wide v1

    .line 843
    invoke-virtual {v4, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 844
    .line 845
    .line 846
    add-int/lit8 p0, p0, 0x8

    .line 847
    .line 848
    goto :goto_1d

    .line 849
    :cond_37
    if-ne p0, v0, :cond_38

    .line 850
    .line 851
    return p0

    .line 852
    :cond_38
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 853
    .line 854
    .line 855
    move-result-object p0

    .line 856
    throw p0

    .line 857
    :cond_39
    if-ne v1, v3, :cond_4e

    .line 858
    .line 859
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 860
    .line 861
    invoke-static {p3, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 862
    .line 863
    .line 864
    move-result-wide v1

    .line 865
    invoke-virtual {v4, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 866
    .line 867
    .line 868
    add-int/lit8 v1, p3, 0x8

    .line 869
    .line 870
    :goto_1e
    if-ge v1, p0, :cond_3b

    .line 871
    .line 872
    invoke-static {p2, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 873
    .line 874
    .line 875
    move-result v2

    .line 876
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 877
    .line 878
    if-eq v0, v3, :cond_3a

    .line 879
    .line 880
    goto :goto_1f

    .line 881
    :cond_3a
    invoke-static {v2, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 882
    .line 883
    .line 884
    move-result-wide v6

    .line 885
    invoke-virtual {v4, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 886
    .line 887
    .line 888
    add-int/lit8 v1, v2, 0x8

    .line 889
    .line 890
    goto :goto_1e

    .line 891
    :cond_3b
    :goto_1f
    return v1

    .line 892
    :pswitch_a
    move p0, p4

    .line 893
    move-object/from16 v5, p13

    .line 894
    .line 895
    if-ne v1, v8, :cond_3e

    .line 896
    .line 897
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/y;

    .line 898
    .line 899
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 900
    .line 901
    .line 902
    move-result p0

    .line 903
    iget v0, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 904
    .line 905
    add-int/2addr v0, p0

    .line 906
    :goto_20
    if-ge p0, v0, :cond_3c

    .line 907
    .line 908
    invoke-static {p2, p0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 909
    .line 910
    .line 911
    move-result p0

    .line 912
    iget v1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 913
    .line 914
    invoke-virtual {v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/y;->e(I)V

    .line 915
    .line 916
    .line 917
    goto :goto_20

    .line 918
    :cond_3c
    if-ne p0, v0, :cond_3d

    .line 919
    .line 920
    return p0

    .line 921
    :cond_3d
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 922
    .line 923
    .line 924
    move-result-object p0

    .line 925
    throw p0

    .line 926
    :cond_3e
    if-nez v1, :cond_4e

    .line 927
    .line 928
    move/from16 p9, p0

    .line 929
    .line 930
    move-object/from16 p7, p2

    .line 931
    .line 932
    move/from16 p8, p3

    .line 933
    .line 934
    move/from16 p6, v0

    .line 935
    .line 936
    move-object/from16 p10, v4

    .line 937
    .line 938
    move-object/from16 p11, v5

    .line 939
    .line 940
    invoke-static/range {p6 .. p11}, Lcom/google/crypto/tink/shaded/protobuf/q0;->q(I[BIILcom/google/crypto/tink/shaded/protobuf/a0;Lcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 941
    .line 942
    .line 943
    move-result p0

    .line 944
    return p0

    .line 945
    :pswitch_b
    move p0, p4

    .line 946
    move-object/from16 v5, p13

    .line 947
    .line 948
    if-ne v1, v8, :cond_41

    .line 949
    .line 950
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 951
    .line 952
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 953
    .line 954
    .line 955
    move-result p0

    .line 956
    iget v0, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 957
    .line 958
    add-int/2addr v0, p0

    .line 959
    :goto_21
    if-ge p0, v0, :cond_3f

    .line 960
    .line 961
    invoke-static {p2, p0, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 962
    .line 963
    .line 964
    move-result p0

    .line 965
    iget-wide v1, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 966
    .line 967
    invoke-virtual {v4, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 968
    .line 969
    .line 970
    goto :goto_21

    .line 971
    :cond_3f
    if-ne p0, v0, :cond_40

    .line 972
    .line 973
    return p0

    .line 974
    :cond_40
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 975
    .line 976
    .line 977
    move-result-object p0

    .line 978
    throw p0

    .line 979
    :cond_41
    if-nez v1, :cond_4e

    .line 980
    .line 981
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/k0;

    .line 982
    .line 983
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 984
    .line 985
    .line 986
    move-result v1

    .line 987
    iget-wide v2, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 988
    .line 989
    invoke-virtual {v4, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 990
    .line 991
    .line 992
    :goto_22
    if-ge v1, p0, :cond_43

    .line 993
    .line 994
    invoke-static {p2, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 995
    .line 996
    .line 997
    move-result v2

    .line 998
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 999
    .line 1000
    if-eq v0, v3, :cond_42

    .line 1001
    .line 1002
    goto :goto_23

    .line 1003
    :cond_42
    invoke-static {p2, v2, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->r([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 1004
    .line 1005
    .line 1006
    move-result v1

    .line 1007
    iget-wide v2, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 1008
    .line 1009
    invoke-virtual {v4, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k0;->e(J)V

    .line 1010
    .line 1011
    .line 1012
    goto :goto_22

    .line 1013
    :cond_43
    :goto_23
    return v1

    .line 1014
    :pswitch_c
    move p0, p4

    .line 1015
    move-object/from16 v5, p13

    .line 1016
    .line 1017
    if-ne v1, v8, :cond_46

    .line 1018
    .line 1019
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/t;

    .line 1020
    .line 1021
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 1022
    .line 1023
    .line 1024
    move-result p0

    .line 1025
    iget v0, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 1026
    .line 1027
    add-int/2addr v0, p0

    .line 1028
    :goto_24
    if-ge p0, v0, :cond_44

    .line 1029
    .line 1030
    invoke-static {p0, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 1031
    .line 1032
    .line 1033
    move-result v1

    .line 1034
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1035
    .line 1036
    .line 1037
    move-result v1

    .line 1038
    invoke-virtual {v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/t;->e(F)V

    .line 1039
    .line 1040
    .line 1041
    add-int/lit8 p0, p0, 0x4

    .line 1042
    .line 1043
    goto :goto_24

    .line 1044
    :cond_44
    if-ne p0, v0, :cond_45

    .line 1045
    .line 1046
    return p0

    .line 1047
    :cond_45
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 1048
    .line 1049
    .line 1050
    move-result-object p0

    .line 1051
    throw p0

    .line 1052
    :cond_46
    if-ne v1, v2, :cond_4e

    .line 1053
    .line 1054
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/t;

    .line 1055
    .line 1056
    invoke-static {p3, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 1057
    .line 1058
    .line 1059
    move-result v1

    .line 1060
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1061
    .line 1062
    .line 1063
    move-result v1

    .line 1064
    invoke-virtual {v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/t;->e(F)V

    .line 1065
    .line 1066
    .line 1067
    add-int/lit8 v1, p3, 0x4

    .line 1068
    .line 1069
    :goto_25
    if-ge v1, p0, :cond_48

    .line 1070
    .line 1071
    invoke-static {p2, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 1072
    .line 1073
    .line 1074
    move-result v2

    .line 1075
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 1076
    .line 1077
    if-eq v0, v3, :cond_47

    .line 1078
    .line 1079
    goto :goto_26

    .line 1080
    :cond_47
    invoke-static {v2, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->f(I[B)I

    .line 1081
    .line 1082
    .line 1083
    move-result v1

    .line 1084
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1085
    .line 1086
    .line 1087
    move-result v1

    .line 1088
    invoke-virtual {v4, v1}, Lcom/google/crypto/tink/shaded/protobuf/t;->e(F)V

    .line 1089
    .line 1090
    .line 1091
    add-int/lit8 v1, v2, 0x4

    .line 1092
    .line 1093
    goto :goto_25

    .line 1094
    :cond_48
    :goto_26
    return v1

    .line 1095
    :pswitch_d
    move p0, p4

    .line 1096
    move-object/from16 v5, p13

    .line 1097
    .line 1098
    if-ne v1, v8, :cond_4b

    .line 1099
    .line 1100
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/n;

    .line 1101
    .line 1102
    invoke-static {p2, p3, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 1103
    .line 1104
    .line 1105
    move-result p0

    .line 1106
    iget v0, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 1107
    .line 1108
    add-int/2addr v0, p0

    .line 1109
    :goto_27
    if-ge p0, v0, :cond_49

    .line 1110
    .line 1111
    invoke-static {p0, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 1112
    .line 1113
    .line 1114
    move-result-wide v1

    .line 1115
    invoke-static {v1, v2}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 1116
    .line 1117
    .line 1118
    move-result-wide v1

    .line 1119
    invoke-virtual {v4, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/n;->e(D)V

    .line 1120
    .line 1121
    .line 1122
    add-int/lit8 p0, p0, 0x8

    .line 1123
    .line 1124
    goto :goto_27

    .line 1125
    :cond_49
    if-ne p0, v0, :cond_4a

    .line 1126
    .line 1127
    return p0

    .line 1128
    :cond_4a
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 1129
    .line 1130
    .line 1131
    move-result-object p0

    .line 1132
    throw p0

    .line 1133
    :cond_4b
    if-ne v1, v3, :cond_4e

    .line 1134
    .line 1135
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/n;

    .line 1136
    .line 1137
    invoke-static {p3, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 1138
    .line 1139
    .line 1140
    move-result-wide v1

    .line 1141
    invoke-static {v1, v2}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 1142
    .line 1143
    .line 1144
    move-result-wide v1

    .line 1145
    invoke-virtual {v4, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/n;->e(D)V

    .line 1146
    .line 1147
    .line 1148
    add-int/lit8 v1, p3, 0x8

    .line 1149
    .line 1150
    :goto_28
    if-ge v1, p0, :cond_4d

    .line 1151
    .line 1152
    invoke-static {p2, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/q0;->p([BILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 1153
    .line 1154
    .line 1155
    move-result v2

    .line 1156
    iget v3, v5, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 1157
    .line 1158
    if-eq v0, v3, :cond_4c

    .line 1159
    .line 1160
    goto :goto_29

    .line 1161
    :cond_4c
    invoke-static {v2, p2}, Lcom/google/crypto/tink/shaded/protobuf/q0;->g(I[B)J

    .line 1162
    .line 1163
    .line 1164
    move-result-wide v6

    .line 1165
    invoke-static {v6, v7}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 1166
    .line 1167
    .line 1168
    move-result-wide v6

    .line 1169
    invoke-virtual {v4, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/n;->e(D)V

    .line 1170
    .line 1171
    .line 1172
    add-int/lit8 v1, v2, 0x8

    .line 1173
    .line 1174
    goto :goto_28

    .line 1175
    :cond_4d
    :goto_29
    return v1

    .line 1176
    :cond_4e
    :goto_2a
    return p3

    .line 1177
    :pswitch_data_0
    .packed-switch 0x12
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_a
        :pswitch_3
        :pswitch_8
        :pswitch_9
        :pswitch_2
        :pswitch_1
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_a
        :pswitch_3
        :pswitch_8
        :pswitch_9
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final H(Ljava/lang/Object;ILandroidx/collection/h;Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)V
    .locals 2

    .line 1
    const v0, 0xfffff

    .line 2
    .line 3
    .line 4
    and-int/2addr p2, v0

    .line 5
    int-to-long v0, p2

    .line 6
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->l:Lcom/google/crypto/tink/shaded/protobuf/j0;

    .line 7
    .line 8
    invoke-virtual {p0, v0, v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    iget-object p1, p3, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 15
    .line 16
    iget p2, p3, Landroidx/collection/h;->e:I

    .line 17
    .line 18
    and-int/lit8 v0, p2, 0x7

    .line 19
    .line 20
    const/4 v1, 0x2

    .line 21
    if-ne v0, v1, :cond_3

    .line 22
    .line 23
    :cond_0
    invoke-virtual {p3, p4, p5}, Landroidx/collection/h;->c0(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-interface {p0, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    invoke-virtual {p1}, Lcom/google/crypto/tink/shaded/protobuf/j;->d()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_2

    .line 35
    .line 36
    iget v0, p3, Landroidx/collection/h;->g:I

    .line 37
    .line 38
    if-eqz v0, :cond_1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    invoke-virtual {p1}, Lcom/google/crypto/tink/shaded/protobuf/j;->l()I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-eq v0, p2, :cond_0

    .line 46
    .line 47
    iput v0, p3, Landroidx/collection/h;->g:I

    .line 48
    .line 49
    :cond_2
    :goto_0
    return-void

    .line 50
    :cond_3
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->b()Lcom/google/crypto/tink/shaded/protobuf/c0;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    throw p0
.end method

.method public final I(ILandroidx/collection/h;Ljava/lang/Object;)V
    .locals 2

    .line 1
    const/high16 v0, 0x20000000

    .line 2
    .line 3
    and-int/2addr v0, p1

    .line 4
    const v1, 0xfffff

    .line 5
    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    and-int p0, p1, v1

    .line 10
    .line 11
    int-to-long p0, p0

    .line 12
    invoke-virtual {p2}, Landroidx/collection/h;->y0()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    invoke-static {p3, p0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    iget-boolean p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->f:Z

    .line 21
    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    and-int p0, p1, v1

    .line 25
    .line 26
    int-to-long p0, p0

    .line 27
    invoke-virtual {p2}, Landroidx/collection/h;->u0()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    invoke-static {p3, p0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_1
    and-int p0, p1, v1

    .line 36
    .line 37
    int-to-long p0, p0

    .line 38
    invoke-virtual {p2}, Landroidx/collection/h;->s()Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    invoke-static {p3, p0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public final K(ILjava/lang/Object;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    add-int/lit8 p1, p1, 0x2

    .line 7
    .line 8
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 9
    .line 10
    aget p0, p0, p1

    .line 11
    .line 12
    ushr-int/lit8 p1, p0, 0x14

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    shl-int p1, v0, p1

    .line 16
    .line 17
    const v0, 0xfffff

    .line 18
    .line 19
    .line 20
    and-int/2addr p0, v0

    .line 21
    int-to-long v0, p0

    .line 22
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 23
    .line 24
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    or-int/2addr p0, p1

    .line 29
    invoke-static {v0, v1, p2, p0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final L(ILjava/lang/Object;I)V
    .locals 2

    .line 1
    add-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p3

    .line 6
    .line 7
    const p3, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int/2addr p0, p3

    .line 11
    int-to-long v0, p0

    .line 12
    invoke-static {v0, v1, p2, p1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final M(II)I
    .locals 4

    .line 1
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    div-int/lit8 v0, v0, 0x3

    .line 5
    .line 6
    add-int/lit8 v0, v0, -0x1

    .line 7
    .line 8
    :goto_0
    if-gt p2, v0, :cond_2

    .line 9
    .line 10
    add-int v1, v0, p2

    .line 11
    .line 12
    ushr-int/lit8 v1, v1, 0x1

    .line 13
    .line 14
    mul-int/lit8 v2, v1, 0x3

    .line 15
    .line 16
    aget v3, p0, v2

    .line 17
    .line 18
    if-ne p1, v3, :cond_0

    .line 19
    .line 20
    return v2

    .line 21
    :cond_0
    if-ge p1, v3, :cond_1

    .line 22
    .line 23
    add-int/lit8 v1, v1, -0x1

    .line 24
    .line 25
    move v0, v1

    .line 26
    goto :goto_0

    .line 27
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 28
    .line 29
    move p2, v1

    .line 30
    goto :goto_0

    .line 31
    :cond_2
    const/4 p0, -0x1

    .line 32
    return p0
.end method

.method public final O(I)I
    .locals 0

    .line 1
    add-int/lit8 p1, p1, 0x1

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p1

    .line 6
    .line 7
    return p0
.end method

.method public final P(Ljava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 8
    .line 9
    array-length v4, v3

    .line 10
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 11
    .line 12
    const/4 v6, -0x1

    .line 13
    const/4 v8, 0x0

    .line 14
    const/4 v9, 0x0

    .line 15
    :goto_0
    if-ge v8, v4, :cond_5

    .line 16
    .line 17
    invoke-virtual {v0, v8}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 18
    .line 19
    .line 20
    move-result v10

    .line 21
    aget v11, v3, v8

    .line 22
    .line 23
    invoke-static {v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 24
    .line 25
    .line 26
    move-result v12

    .line 27
    iget-boolean v13, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->g:Z

    .line 28
    .line 29
    const/4 v15, 0x1

    .line 30
    if-nez v13, :cond_1

    .line 31
    .line 32
    const/16 v13, 0x11

    .line 33
    .line 34
    if-gt v12, v13, :cond_1

    .line 35
    .line 36
    add-int/lit8 v13, v8, 0x2

    .line 37
    .line 38
    aget v13, v3, v13

    .line 39
    .line 40
    const v16, 0xfffff

    .line 41
    .line 42
    .line 43
    and-int v14, v13, v16

    .line 44
    .line 45
    move/from16 v17, v8

    .line 46
    .line 47
    if-eq v14, v6, :cond_0

    .line 48
    .line 49
    int-to-long v7, v14

    .line 50
    invoke-virtual {v5, v1, v7, v8}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 51
    .line 52
    .line 53
    move-result v9

    .line 54
    move v6, v14

    .line 55
    :cond_0
    ushr-int/lit8 v7, v13, 0x14

    .line 56
    .line 57
    shl-int v7, v15, v7

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    move/from16 v17, v8

    .line 61
    .line 62
    const v16, 0xfffff

    .line 63
    .line 64
    .line 65
    const/4 v7, 0x0

    .line 66
    :goto_1
    and-int v8, v10, v16

    .line 67
    .line 68
    int-to-long v13, v8

    .line 69
    const/16 v8, 0x3f

    .line 70
    .line 71
    packed-switch v12, :pswitch_data_0

    .line 72
    .line 73
    .line 74
    move/from16 v10, v17

    .line 75
    .line 76
    :cond_2
    :goto_2
    const/4 v12, 0x0

    .line 77
    goto/16 :goto_3

    .line 78
    .line 79
    :pswitch_0
    move/from16 v10, v17

    .line 80
    .line 81
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 82
    .line 83
    .line 84
    move-result v7

    .line 85
    if-eqz v7, :cond_2

    .line 86
    .line 87
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v7

    .line 91
    invoke-virtual {v0, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 92
    .line 93
    .line 94
    move-result-object v8

    .line 95
    invoke-virtual {v2, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/m;->b(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 96
    .line 97
    .line 98
    goto :goto_2

    .line 99
    :pswitch_1
    move/from16 v10, v17

    .line 100
    .line 101
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 102
    .line 103
    .line 104
    move-result v7

    .line 105
    if-eqz v7, :cond_2

    .line 106
    .line 107
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 108
    .line 109
    .line 110
    move-result-wide v12

    .line 111
    iget-object v7, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v7, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 114
    .line 115
    shl-long v14, v12, v15

    .line 116
    .line 117
    shr-long/2addr v12, v8

    .line 118
    xor-long/2addr v12, v14

    .line 119
    invoke-virtual {v7, v11, v12, v13}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 120
    .line 121
    .line 122
    goto :goto_2

    .line 123
    :pswitch_2
    move/from16 v10, v17

    .line 124
    .line 125
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 126
    .line 127
    .line 128
    move-result v7

    .line 129
    if-eqz v7, :cond_2

    .line 130
    .line 131
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 132
    .line 133
    .line 134
    move-result v7

    .line 135
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 138
    .line 139
    shl-int/lit8 v12, v7, 0x1

    .line 140
    .line 141
    shr-int/lit8 v7, v7, 0x1f

    .line 142
    .line 143
    xor-int/2addr v7, v12

    .line 144
    const/4 v12, 0x0

    .line 145
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 149
    .line 150
    .line 151
    goto :goto_2

    .line 152
    :pswitch_3
    move/from16 v10, v17

    .line 153
    .line 154
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 155
    .line 156
    .line 157
    move-result v7

    .line 158
    if-eqz v7, :cond_2

    .line 159
    .line 160
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 161
    .line 162
    .line 163
    move-result-wide v7

    .line 164
    iget-object v12, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast v12, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 167
    .line 168
    invoke-virtual {v12, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 169
    .line 170
    .line 171
    goto :goto_2

    .line 172
    :pswitch_4
    move/from16 v10, v17

    .line 173
    .line 174
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 175
    .line 176
    .line 177
    move-result v7

    .line 178
    if-eqz v7, :cond_2

    .line 179
    .line 180
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 181
    .line 182
    .line 183
    move-result v7

    .line 184
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 187
    .line 188
    invoke-virtual {v8, v11, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 189
    .line 190
    .line 191
    goto :goto_2

    .line 192
    :pswitch_5
    move/from16 v10, v17

    .line 193
    .line 194
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 195
    .line 196
    .line 197
    move-result v7

    .line 198
    if-eqz v7, :cond_2

    .line 199
    .line 200
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 201
    .line 202
    .line 203
    move-result v7

    .line 204
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 207
    .line 208
    const/4 v12, 0x0

    .line 209
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->P(I)V

    .line 213
    .line 214
    .line 215
    goto/16 :goto_3

    .line 216
    .line 217
    :pswitch_6
    move/from16 v10, v17

    .line 218
    .line 219
    const/4 v12, 0x0

    .line 220
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 221
    .line 222
    .line 223
    move-result v7

    .line 224
    if-eqz v7, :cond_4

    .line 225
    .line 226
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 227
    .line 228
    .line 229
    move-result v7

    .line 230
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 233
    .line 234
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 238
    .line 239
    .line 240
    goto/16 :goto_2

    .line 241
    .line 242
    :pswitch_7
    move/from16 v10, v17

    .line 243
    .line 244
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 245
    .line 246
    .line 247
    move-result v7

    .line 248
    if-eqz v7, :cond_2

    .line 249
    .line 250
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v7

    .line 254
    check-cast v7, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 255
    .line 256
    invoke-virtual {v2, v11, v7}, Lcom/google/crypto/tink/shaded/protobuf/m;->a(ILcom/google/crypto/tink/shaded/protobuf/i;)V

    .line 257
    .line 258
    .line 259
    goto/16 :goto_2

    .line 260
    .line 261
    :pswitch_8
    move/from16 v10, v17

    .line 262
    .line 263
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 264
    .line 265
    .line 266
    move-result v7

    .line 267
    if-eqz v7, :cond_2

    .line 268
    .line 269
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v7

    .line 273
    invoke-virtual {v0, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 274
    .line 275
    .line 276
    move-result-object v8

    .line 277
    invoke-virtual {v2, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/m;->c(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 278
    .line 279
    .line 280
    goto/16 :goto_2

    .line 281
    .line 282
    :pswitch_9
    move/from16 v10, v17

    .line 283
    .line 284
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 285
    .line 286
    .line 287
    move-result v7

    .line 288
    if-eqz v7, :cond_2

    .line 289
    .line 290
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v7

    .line 294
    invoke-static {v11, v7, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->Q(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 295
    .line 296
    .line 297
    goto/16 :goto_2

    .line 298
    .line 299
    :pswitch_a
    move/from16 v10, v17

    .line 300
    .line 301
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 302
    .line 303
    .line 304
    move-result v7

    .line 305
    if-eqz v7, :cond_2

    .line 306
    .line 307
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 308
    .line 309
    invoke-virtual {v7, v1, v13, v14}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v7

    .line 313
    check-cast v7, Ljava/lang/Boolean;

    .line 314
    .line 315
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 316
    .line 317
    .line 318
    move-result v7

    .line 319
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 320
    .line 321
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 322
    .line 323
    const/4 v12, 0x0

    .line 324
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 325
    .line 326
    .line 327
    int-to-byte v7, v7

    .line 328
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->J(B)V

    .line 329
    .line 330
    .line 331
    goto/16 :goto_2

    .line 332
    .line 333
    :pswitch_b
    move/from16 v10, v17

    .line 334
    .line 335
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 336
    .line 337
    .line 338
    move-result v7

    .line 339
    if-eqz v7, :cond_2

    .line 340
    .line 341
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 342
    .line 343
    .line 344
    move-result v7

    .line 345
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 346
    .line 347
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 348
    .line 349
    invoke-virtual {v8, v11, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 350
    .line 351
    .line 352
    goto/16 :goto_2

    .line 353
    .line 354
    :pswitch_c
    move/from16 v10, v17

    .line 355
    .line 356
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 357
    .line 358
    .line 359
    move-result v7

    .line 360
    if-eqz v7, :cond_2

    .line 361
    .line 362
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 363
    .line 364
    .line 365
    move-result-wide v7

    .line 366
    iget-object v12, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 367
    .line 368
    check-cast v12, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 369
    .line 370
    invoke-virtual {v12, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 371
    .line 372
    .line 373
    goto/16 :goto_2

    .line 374
    .line 375
    :pswitch_d
    move/from16 v10, v17

    .line 376
    .line 377
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 378
    .line 379
    .line 380
    move-result v7

    .line 381
    if-eqz v7, :cond_2

    .line 382
    .line 383
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 384
    .line 385
    .line 386
    move-result v7

    .line 387
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 388
    .line 389
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 390
    .line 391
    const/4 v12, 0x0

    .line 392
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 393
    .line 394
    .line 395
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->P(I)V

    .line 396
    .line 397
    .line 398
    goto/16 :goto_2

    .line 399
    .line 400
    :pswitch_e
    move/from16 v10, v17

    .line 401
    .line 402
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 403
    .line 404
    .line 405
    move-result v7

    .line 406
    if-eqz v7, :cond_2

    .line 407
    .line 408
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 409
    .line 410
    .line 411
    move-result-wide v7

    .line 412
    iget-object v12, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 413
    .line 414
    check-cast v12, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 415
    .line 416
    invoke-virtual {v12, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 417
    .line 418
    .line 419
    goto/16 :goto_2

    .line 420
    .line 421
    :pswitch_f
    move/from16 v10, v17

    .line 422
    .line 423
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 424
    .line 425
    .line 426
    move-result v7

    .line 427
    if-eqz v7, :cond_2

    .line 428
    .line 429
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 430
    .line 431
    .line 432
    move-result-wide v7

    .line 433
    iget-object v12, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 434
    .line 435
    check-cast v12, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 436
    .line 437
    invoke-virtual {v12, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 438
    .line 439
    .line 440
    goto/16 :goto_2

    .line 441
    .line 442
    :pswitch_10
    move/from16 v10, v17

    .line 443
    .line 444
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 445
    .line 446
    .line 447
    move-result v7

    .line 448
    if-eqz v7, :cond_2

    .line 449
    .line 450
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 451
    .line 452
    invoke-virtual {v7, v1, v13, v14}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    move-result-object v7

    .line 456
    check-cast v7, Ljava/lang/Float;

    .line 457
    .line 458
    invoke-virtual {v7}, Ljava/lang/Float;->floatValue()F

    .line 459
    .line 460
    .line 461
    move-result v7

    .line 462
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 463
    .line 464
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 465
    .line 466
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 467
    .line 468
    .line 469
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 470
    .line 471
    .line 472
    move-result v7

    .line 473
    invoke-virtual {v8, v11, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 474
    .line 475
    .line 476
    goto/16 :goto_2

    .line 477
    .line 478
    :pswitch_11
    move/from16 v10, v17

    .line 479
    .line 480
    invoke-virtual {v0, v11, v1, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 481
    .line 482
    .line 483
    move-result v7

    .line 484
    if-eqz v7, :cond_2

    .line 485
    .line 486
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 487
    .line 488
    invoke-virtual {v7, v1, v13, v14}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v7

    .line 492
    check-cast v7, Ljava/lang/Double;

    .line 493
    .line 494
    invoke-virtual {v7}, Ljava/lang/Double;->doubleValue()D

    .line 495
    .line 496
    .line 497
    move-result-wide v7

    .line 498
    iget-object v12, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 499
    .line 500
    check-cast v12, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 501
    .line 502
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 503
    .line 504
    .line 505
    invoke-static {v7, v8}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 506
    .line 507
    .line 508
    move-result-wide v7

    .line 509
    invoke-virtual {v12, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 510
    .line 511
    .line 512
    goto/16 :goto_2

    .line 513
    .line 514
    :pswitch_12
    move/from16 v10, v17

    .line 515
    .line 516
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    move-result-object v7

    .line 520
    if-nez v7, :cond_3

    .line 521
    .line 522
    goto/16 :goto_2

    .line 523
    .line 524
    :cond_3
    invoke-virtual {v0, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->n(I)Ljava/lang/Object;

    .line 525
    .line 526
    .line 527
    move-result-object v1

    .line 528
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 529
    .line 530
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 531
    .line 532
    .line 533
    invoke-static {v1}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 534
    .line 535
    .line 536
    const/4 v0, 0x0

    .line 537
    throw v0

    .line 538
    :pswitch_13
    move/from16 v10, v17

    .line 539
    .line 540
    aget v7, v3, v10

    .line 541
    .line 542
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 543
    .line 544
    .line 545
    move-result-object v8

    .line 546
    check-cast v8, Ljava/util/List;

    .line 547
    .line 548
    invoke-virtual {v0, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 549
    .line 550
    .line 551
    move-result-object v11

    .line 552
    invoke-static {v7, v8, v2, v11}, Lcom/google/crypto/tink/shaded/protobuf/b1;->G(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 553
    .line 554
    .line 555
    goto/16 :goto_2

    .line 556
    .line 557
    :pswitch_14
    move/from16 v10, v17

    .line 558
    .line 559
    aget v7, v3, v10

    .line 560
    .line 561
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 562
    .line 563
    .line 564
    move-result-object v8

    .line 565
    check-cast v8, Ljava/util/List;

    .line 566
    .line 567
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->N(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 568
    .line 569
    .line 570
    goto/16 :goto_2

    .line 571
    .line 572
    :pswitch_15
    move/from16 v10, v17

    .line 573
    .line 574
    aget v7, v3, v10

    .line 575
    .line 576
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 577
    .line 578
    .line 579
    move-result-object v8

    .line 580
    check-cast v8, Ljava/util/List;

    .line 581
    .line 582
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->M(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 583
    .line 584
    .line 585
    goto/16 :goto_2

    .line 586
    .line 587
    :pswitch_16
    move/from16 v10, v17

    .line 588
    .line 589
    aget v7, v3, v10

    .line 590
    .line 591
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 592
    .line 593
    .line 594
    move-result-object v8

    .line 595
    check-cast v8, Ljava/util/List;

    .line 596
    .line 597
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->L(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 598
    .line 599
    .line 600
    goto/16 :goto_2

    .line 601
    .line 602
    :pswitch_17
    move/from16 v10, v17

    .line 603
    .line 604
    aget v7, v3, v10

    .line 605
    .line 606
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 607
    .line 608
    .line 609
    move-result-object v8

    .line 610
    check-cast v8, Ljava/util/List;

    .line 611
    .line 612
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->K(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 613
    .line 614
    .line 615
    goto/16 :goto_2

    .line 616
    .line 617
    :pswitch_18
    move/from16 v10, v17

    .line 618
    .line 619
    aget v7, v3, v10

    .line 620
    .line 621
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 622
    .line 623
    .line 624
    move-result-object v8

    .line 625
    check-cast v8, Ljava/util/List;

    .line 626
    .line 627
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->C(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 628
    .line 629
    .line 630
    goto/16 :goto_2

    .line 631
    .line 632
    :pswitch_19
    move/from16 v10, v17

    .line 633
    .line 634
    aget v7, v3, v10

    .line 635
    .line 636
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 637
    .line 638
    .line 639
    move-result-object v8

    .line 640
    check-cast v8, Ljava/util/List;

    .line 641
    .line 642
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->P(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 643
    .line 644
    .line 645
    goto/16 :goto_2

    .line 646
    .line 647
    :pswitch_1a
    move/from16 v10, v17

    .line 648
    .line 649
    aget v7, v3, v10

    .line 650
    .line 651
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    move-result-object v8

    .line 655
    check-cast v8, Ljava/util/List;

    .line 656
    .line 657
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->z(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 658
    .line 659
    .line 660
    goto/16 :goto_2

    .line 661
    .line 662
    :pswitch_1b
    move/from16 v10, v17

    .line 663
    .line 664
    aget v7, v3, v10

    .line 665
    .line 666
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 667
    .line 668
    .line 669
    move-result-object v8

    .line 670
    check-cast v8, Ljava/util/List;

    .line 671
    .line 672
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->D(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 673
    .line 674
    .line 675
    goto/16 :goto_2

    .line 676
    .line 677
    :pswitch_1c
    move/from16 v10, v17

    .line 678
    .line 679
    aget v7, v3, v10

    .line 680
    .line 681
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 682
    .line 683
    .line 684
    move-result-object v8

    .line 685
    check-cast v8, Ljava/util/List;

    .line 686
    .line 687
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->E(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 688
    .line 689
    .line 690
    goto/16 :goto_2

    .line 691
    .line 692
    :pswitch_1d
    move/from16 v10, v17

    .line 693
    .line 694
    aget v7, v3, v10

    .line 695
    .line 696
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 697
    .line 698
    .line 699
    move-result-object v8

    .line 700
    check-cast v8, Ljava/util/List;

    .line 701
    .line 702
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->H(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 703
    .line 704
    .line 705
    goto/16 :goto_2

    .line 706
    .line 707
    :pswitch_1e
    move/from16 v10, v17

    .line 708
    .line 709
    aget v7, v3, v10

    .line 710
    .line 711
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 712
    .line 713
    .line 714
    move-result-object v8

    .line 715
    check-cast v8, Ljava/util/List;

    .line 716
    .line 717
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->Q(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 718
    .line 719
    .line 720
    goto/16 :goto_2

    .line 721
    .line 722
    :pswitch_1f
    move/from16 v10, v17

    .line 723
    .line 724
    aget v7, v3, v10

    .line 725
    .line 726
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 727
    .line 728
    .line 729
    move-result-object v8

    .line 730
    check-cast v8, Ljava/util/List;

    .line 731
    .line 732
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->I(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 733
    .line 734
    .line 735
    goto/16 :goto_2

    .line 736
    .line 737
    :pswitch_20
    move/from16 v10, v17

    .line 738
    .line 739
    aget v7, v3, v10

    .line 740
    .line 741
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 742
    .line 743
    .line 744
    move-result-object v8

    .line 745
    check-cast v8, Ljava/util/List;

    .line 746
    .line 747
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->F(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 748
    .line 749
    .line 750
    goto/16 :goto_2

    .line 751
    .line 752
    :pswitch_21
    move/from16 v10, v17

    .line 753
    .line 754
    aget v7, v3, v10

    .line 755
    .line 756
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 757
    .line 758
    .line 759
    move-result-object v8

    .line 760
    check-cast v8, Ljava/util/List;

    .line 761
    .line 762
    invoke-static {v7, v8, v2, v15}, Lcom/google/crypto/tink/shaded/protobuf/b1;->B(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 763
    .line 764
    .line 765
    goto/16 :goto_2

    .line 766
    .line 767
    :pswitch_22
    move/from16 v10, v17

    .line 768
    .line 769
    aget v7, v3, v10

    .line 770
    .line 771
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 772
    .line 773
    .line 774
    move-result-object v8

    .line 775
    check-cast v8, Ljava/util/List;

    .line 776
    .line 777
    const/4 v12, 0x0

    .line 778
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->N(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 779
    .line 780
    .line 781
    goto/16 :goto_3

    .line 782
    .line 783
    :pswitch_23
    move/from16 v10, v17

    .line 784
    .line 785
    const/4 v12, 0x0

    .line 786
    aget v7, v3, v10

    .line 787
    .line 788
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 789
    .line 790
    .line 791
    move-result-object v8

    .line 792
    check-cast v8, Ljava/util/List;

    .line 793
    .line 794
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->M(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 795
    .line 796
    .line 797
    goto/16 :goto_3

    .line 798
    .line 799
    :pswitch_24
    move/from16 v10, v17

    .line 800
    .line 801
    const/4 v12, 0x0

    .line 802
    aget v7, v3, v10

    .line 803
    .line 804
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 805
    .line 806
    .line 807
    move-result-object v8

    .line 808
    check-cast v8, Ljava/util/List;

    .line 809
    .line 810
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->L(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 811
    .line 812
    .line 813
    goto/16 :goto_3

    .line 814
    .line 815
    :pswitch_25
    move/from16 v10, v17

    .line 816
    .line 817
    const/4 v12, 0x0

    .line 818
    aget v7, v3, v10

    .line 819
    .line 820
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 821
    .line 822
    .line 823
    move-result-object v8

    .line 824
    check-cast v8, Ljava/util/List;

    .line 825
    .line 826
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->K(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 827
    .line 828
    .line 829
    goto/16 :goto_3

    .line 830
    .line 831
    :pswitch_26
    move/from16 v10, v17

    .line 832
    .line 833
    const/4 v12, 0x0

    .line 834
    aget v7, v3, v10

    .line 835
    .line 836
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 837
    .line 838
    .line 839
    move-result-object v8

    .line 840
    check-cast v8, Ljava/util/List;

    .line 841
    .line 842
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->C(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 843
    .line 844
    .line 845
    goto/16 :goto_3

    .line 846
    .line 847
    :pswitch_27
    move/from16 v10, v17

    .line 848
    .line 849
    const/4 v12, 0x0

    .line 850
    aget v7, v3, v10

    .line 851
    .line 852
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 853
    .line 854
    .line 855
    move-result-object v8

    .line 856
    check-cast v8, Ljava/util/List;

    .line 857
    .line 858
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->P(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 859
    .line 860
    .line 861
    goto/16 :goto_3

    .line 862
    .line 863
    :pswitch_28
    move/from16 v10, v17

    .line 864
    .line 865
    aget v7, v3, v10

    .line 866
    .line 867
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 868
    .line 869
    .line 870
    move-result-object v8

    .line 871
    check-cast v8, Ljava/util/List;

    .line 872
    .line 873
    invoke-static {v7, v8, v2}, Lcom/google/crypto/tink/shaded/protobuf/b1;->A(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 874
    .line 875
    .line 876
    goto/16 :goto_2

    .line 877
    .line 878
    :pswitch_29
    move/from16 v10, v17

    .line 879
    .line 880
    aget v7, v3, v10

    .line 881
    .line 882
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 883
    .line 884
    .line 885
    move-result-object v8

    .line 886
    check-cast v8, Ljava/util/List;

    .line 887
    .line 888
    invoke-virtual {v0, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 889
    .line 890
    .line 891
    move-result-object v11

    .line 892
    invoke-static {v7, v8, v2, v11}, Lcom/google/crypto/tink/shaded/protobuf/b1;->J(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 893
    .line 894
    .line 895
    goto/16 :goto_2

    .line 896
    .line 897
    :pswitch_2a
    move/from16 v10, v17

    .line 898
    .line 899
    aget v7, v3, v10

    .line 900
    .line 901
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 902
    .line 903
    .line 904
    move-result-object v8

    .line 905
    check-cast v8, Ljava/util/List;

    .line 906
    .line 907
    invoke-static {v7, v8, v2}, Lcom/google/crypto/tink/shaded/protobuf/b1;->O(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 908
    .line 909
    .line 910
    goto/16 :goto_2

    .line 911
    .line 912
    :pswitch_2b
    move/from16 v10, v17

    .line 913
    .line 914
    aget v7, v3, v10

    .line 915
    .line 916
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 917
    .line 918
    .line 919
    move-result-object v8

    .line 920
    check-cast v8, Ljava/util/List;

    .line 921
    .line 922
    const/4 v12, 0x0

    .line 923
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->z(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 924
    .line 925
    .line 926
    goto/16 :goto_3

    .line 927
    .line 928
    :pswitch_2c
    move/from16 v10, v17

    .line 929
    .line 930
    const/4 v12, 0x0

    .line 931
    aget v7, v3, v10

    .line 932
    .line 933
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 934
    .line 935
    .line 936
    move-result-object v8

    .line 937
    check-cast v8, Ljava/util/List;

    .line 938
    .line 939
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->D(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 940
    .line 941
    .line 942
    goto/16 :goto_3

    .line 943
    .line 944
    :pswitch_2d
    move/from16 v10, v17

    .line 945
    .line 946
    const/4 v12, 0x0

    .line 947
    aget v7, v3, v10

    .line 948
    .line 949
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 950
    .line 951
    .line 952
    move-result-object v8

    .line 953
    check-cast v8, Ljava/util/List;

    .line 954
    .line 955
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->E(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 956
    .line 957
    .line 958
    goto/16 :goto_3

    .line 959
    .line 960
    :pswitch_2e
    move/from16 v10, v17

    .line 961
    .line 962
    const/4 v12, 0x0

    .line 963
    aget v7, v3, v10

    .line 964
    .line 965
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 966
    .line 967
    .line 968
    move-result-object v8

    .line 969
    check-cast v8, Ljava/util/List;

    .line 970
    .line 971
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->H(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 972
    .line 973
    .line 974
    goto/16 :goto_3

    .line 975
    .line 976
    :pswitch_2f
    move/from16 v10, v17

    .line 977
    .line 978
    const/4 v12, 0x0

    .line 979
    aget v7, v3, v10

    .line 980
    .line 981
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 982
    .line 983
    .line 984
    move-result-object v8

    .line 985
    check-cast v8, Ljava/util/List;

    .line 986
    .line 987
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->Q(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 988
    .line 989
    .line 990
    goto/16 :goto_3

    .line 991
    .line 992
    :pswitch_30
    move/from16 v10, v17

    .line 993
    .line 994
    const/4 v12, 0x0

    .line 995
    aget v7, v3, v10

    .line 996
    .line 997
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 998
    .line 999
    .line 1000
    move-result-object v8

    .line 1001
    check-cast v8, Ljava/util/List;

    .line 1002
    .line 1003
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->I(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 1004
    .line 1005
    .line 1006
    goto/16 :goto_3

    .line 1007
    .line 1008
    :pswitch_31
    move/from16 v10, v17

    .line 1009
    .line 1010
    const/4 v12, 0x0

    .line 1011
    aget v7, v3, v10

    .line 1012
    .line 1013
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v8

    .line 1017
    check-cast v8, Ljava/util/List;

    .line 1018
    .line 1019
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->F(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 1020
    .line 1021
    .line 1022
    goto/16 :goto_3

    .line 1023
    .line 1024
    :pswitch_32
    move/from16 v10, v17

    .line 1025
    .line 1026
    const/4 v12, 0x0

    .line 1027
    aget v7, v3, v10

    .line 1028
    .line 1029
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1030
    .line 1031
    .line 1032
    move-result-object v8

    .line 1033
    check-cast v8, Ljava/util/List;

    .line 1034
    .line 1035
    invoke-static {v7, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->B(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 1036
    .line 1037
    .line 1038
    goto/16 :goto_3

    .line 1039
    .line 1040
    :pswitch_33
    move/from16 v10, v17

    .line 1041
    .line 1042
    and-int/2addr v7, v9

    .line 1043
    if-eqz v7, :cond_2

    .line 1044
    .line 1045
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1046
    .line 1047
    .line 1048
    move-result-object v7

    .line 1049
    invoke-virtual {v0, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1050
    .line 1051
    .line 1052
    move-result-object v8

    .line 1053
    invoke-virtual {v2, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/m;->b(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 1054
    .line 1055
    .line 1056
    goto/16 :goto_2

    .line 1057
    .line 1058
    :pswitch_34
    move/from16 v10, v17

    .line 1059
    .line 1060
    and-int/2addr v7, v9

    .line 1061
    if-eqz v7, :cond_2

    .line 1062
    .line 1063
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1064
    .line 1065
    .line 1066
    move-result-wide v12

    .line 1067
    iget-object v7, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1068
    .line 1069
    check-cast v7, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1070
    .line 1071
    shl-long v14, v12, v15

    .line 1072
    .line 1073
    shr-long/2addr v12, v8

    .line 1074
    xor-long/2addr v12, v14

    .line 1075
    invoke-virtual {v7, v11, v12, v13}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 1076
    .line 1077
    .line 1078
    goto/16 :goto_2

    .line 1079
    .line 1080
    :pswitch_35
    move/from16 v10, v17

    .line 1081
    .line 1082
    and-int/2addr v7, v9

    .line 1083
    if-eqz v7, :cond_2

    .line 1084
    .line 1085
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1086
    .line 1087
    .line 1088
    move-result v7

    .line 1089
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1090
    .line 1091
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1092
    .line 1093
    shl-int/lit8 v12, v7, 0x1

    .line 1094
    .line 1095
    shr-int/lit8 v7, v7, 0x1f

    .line 1096
    .line 1097
    xor-int/2addr v7, v12

    .line 1098
    const/4 v12, 0x0

    .line 1099
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1100
    .line 1101
    .line 1102
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 1103
    .line 1104
    .line 1105
    goto/16 :goto_2

    .line 1106
    .line 1107
    :pswitch_36
    move/from16 v10, v17

    .line 1108
    .line 1109
    and-int/2addr v7, v9

    .line 1110
    if-eqz v7, :cond_2

    .line 1111
    .line 1112
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1113
    .line 1114
    .line 1115
    move-result-wide v7

    .line 1116
    iget-object v12, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1117
    .line 1118
    check-cast v12, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1119
    .line 1120
    invoke-virtual {v12, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 1121
    .line 1122
    .line 1123
    goto/16 :goto_2

    .line 1124
    .line 1125
    :pswitch_37
    move/from16 v10, v17

    .line 1126
    .line 1127
    and-int/2addr v7, v9

    .line 1128
    if-eqz v7, :cond_2

    .line 1129
    .line 1130
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1131
    .line 1132
    .line 1133
    move-result v7

    .line 1134
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1135
    .line 1136
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1137
    .line 1138
    invoke-virtual {v8, v11, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 1139
    .line 1140
    .line 1141
    goto/16 :goto_2

    .line 1142
    .line 1143
    :pswitch_38
    move/from16 v10, v17

    .line 1144
    .line 1145
    and-int/2addr v7, v9

    .line 1146
    if-eqz v7, :cond_2

    .line 1147
    .line 1148
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1149
    .line 1150
    .line 1151
    move-result v7

    .line 1152
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1153
    .line 1154
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1155
    .line 1156
    const/4 v12, 0x0

    .line 1157
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1158
    .line 1159
    .line 1160
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->P(I)V

    .line 1161
    .line 1162
    .line 1163
    goto/16 :goto_3

    .line 1164
    .line 1165
    :pswitch_39
    move/from16 v10, v17

    .line 1166
    .line 1167
    const/4 v12, 0x0

    .line 1168
    and-int/2addr v7, v9

    .line 1169
    if-eqz v7, :cond_4

    .line 1170
    .line 1171
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1172
    .line 1173
    .line 1174
    move-result v7

    .line 1175
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1176
    .line 1177
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1178
    .line 1179
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1180
    .line 1181
    .line 1182
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 1183
    .line 1184
    .line 1185
    goto/16 :goto_2

    .line 1186
    .line 1187
    :pswitch_3a
    move/from16 v10, v17

    .line 1188
    .line 1189
    and-int/2addr v7, v9

    .line 1190
    if-eqz v7, :cond_2

    .line 1191
    .line 1192
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v7

    .line 1196
    check-cast v7, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 1197
    .line 1198
    invoke-virtual {v2, v11, v7}, Lcom/google/crypto/tink/shaded/protobuf/m;->a(ILcom/google/crypto/tink/shaded/protobuf/i;)V

    .line 1199
    .line 1200
    .line 1201
    goto/16 :goto_2

    .line 1202
    .line 1203
    :pswitch_3b
    move/from16 v10, v17

    .line 1204
    .line 1205
    and-int/2addr v7, v9

    .line 1206
    if-eqz v7, :cond_2

    .line 1207
    .line 1208
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1209
    .line 1210
    .line 1211
    move-result-object v7

    .line 1212
    invoke-virtual {v0, v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1213
    .line 1214
    .line 1215
    move-result-object v8

    .line 1216
    invoke-virtual {v2, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/m;->c(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 1217
    .line 1218
    .line 1219
    goto/16 :goto_2

    .line 1220
    .line 1221
    :pswitch_3c
    move/from16 v10, v17

    .line 1222
    .line 1223
    and-int/2addr v7, v9

    .line 1224
    if-eqz v7, :cond_2

    .line 1225
    .line 1226
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v7

    .line 1230
    invoke-static {v11, v7, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->Q(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 1231
    .line 1232
    .line 1233
    goto/16 :goto_2

    .line 1234
    .line 1235
    :pswitch_3d
    move/from16 v10, v17

    .line 1236
    .line 1237
    and-int/2addr v7, v9

    .line 1238
    if-eqz v7, :cond_2

    .line 1239
    .line 1240
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1241
    .line 1242
    invoke-virtual {v7, v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->c(JLjava/lang/Object;)Z

    .line 1243
    .line 1244
    .line 1245
    move-result v7

    .line 1246
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1247
    .line 1248
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1249
    .line 1250
    const/4 v12, 0x0

    .line 1251
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1252
    .line 1253
    .line 1254
    int-to-byte v7, v7

    .line 1255
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->J(B)V

    .line 1256
    .line 1257
    .line 1258
    goto/16 :goto_2

    .line 1259
    .line 1260
    :pswitch_3e
    move/from16 v10, v17

    .line 1261
    .line 1262
    and-int/2addr v7, v9

    .line 1263
    if-eqz v7, :cond_2

    .line 1264
    .line 1265
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1266
    .line 1267
    .line 1268
    move-result v7

    .line 1269
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1270
    .line 1271
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1272
    .line 1273
    invoke-virtual {v8, v11, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 1274
    .line 1275
    .line 1276
    goto/16 :goto_2

    .line 1277
    .line 1278
    :pswitch_3f
    move/from16 v10, v17

    .line 1279
    .line 1280
    and-int/2addr v7, v9

    .line 1281
    if-eqz v7, :cond_2

    .line 1282
    .line 1283
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1284
    .line 1285
    .line 1286
    move-result-wide v7

    .line 1287
    iget-object v12, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1288
    .line 1289
    check-cast v12, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1290
    .line 1291
    invoke-virtual {v12, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 1292
    .line 1293
    .line 1294
    goto/16 :goto_2

    .line 1295
    .line 1296
    :pswitch_40
    move/from16 v10, v17

    .line 1297
    .line 1298
    and-int/2addr v7, v9

    .line 1299
    if-eqz v7, :cond_2

    .line 1300
    .line 1301
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1302
    .line 1303
    .line 1304
    move-result v7

    .line 1305
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1306
    .line 1307
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1308
    .line 1309
    const/4 v12, 0x0

    .line 1310
    invoke-virtual {v8, v11, v12}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1311
    .line 1312
    .line 1313
    invoke-virtual {v8, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->P(I)V

    .line 1314
    .line 1315
    .line 1316
    goto :goto_3

    .line 1317
    :pswitch_41
    move/from16 v10, v17

    .line 1318
    .line 1319
    const/4 v12, 0x0

    .line 1320
    and-int/2addr v7, v9

    .line 1321
    if-eqz v7, :cond_4

    .line 1322
    .line 1323
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1324
    .line 1325
    .line 1326
    move-result-wide v7

    .line 1327
    iget-object v13, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1328
    .line 1329
    check-cast v13, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1330
    .line 1331
    invoke-virtual {v13, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 1332
    .line 1333
    .line 1334
    goto :goto_3

    .line 1335
    :pswitch_42
    move/from16 v10, v17

    .line 1336
    .line 1337
    const/4 v12, 0x0

    .line 1338
    and-int/2addr v7, v9

    .line 1339
    if-eqz v7, :cond_4

    .line 1340
    .line 1341
    invoke-virtual {v5, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1342
    .line 1343
    .line 1344
    move-result-wide v7

    .line 1345
    iget-object v13, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1346
    .line 1347
    check-cast v13, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1348
    .line 1349
    invoke-virtual {v13, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 1350
    .line 1351
    .line 1352
    goto :goto_3

    .line 1353
    :pswitch_43
    move/from16 v10, v17

    .line 1354
    .line 1355
    const/4 v12, 0x0

    .line 1356
    and-int/2addr v7, v9

    .line 1357
    if-eqz v7, :cond_4

    .line 1358
    .line 1359
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1360
    .line 1361
    invoke-virtual {v7, v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->f(JLjava/lang/Object;)F

    .line 1362
    .line 1363
    .line 1364
    move-result v7

    .line 1365
    iget-object v8, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1366
    .line 1367
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1368
    .line 1369
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1370
    .line 1371
    .line 1372
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1373
    .line 1374
    .line 1375
    move-result v7

    .line 1376
    invoke-virtual {v8, v11, v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 1377
    .line 1378
    .line 1379
    goto :goto_3

    .line 1380
    :pswitch_44
    move/from16 v10, v17

    .line 1381
    .line 1382
    const/4 v12, 0x0

    .line 1383
    and-int/2addr v7, v9

    .line 1384
    if-eqz v7, :cond_4

    .line 1385
    .line 1386
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1387
    .line 1388
    invoke-virtual {v7, v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->e(JLjava/lang/Object;)D

    .line 1389
    .line 1390
    .line 1391
    move-result-wide v7

    .line 1392
    iget-object v13, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 1393
    .line 1394
    check-cast v13, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 1395
    .line 1396
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1397
    .line 1398
    .line 1399
    invoke-static {v7, v8}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 1400
    .line 1401
    .line 1402
    move-result-wide v7

    .line 1403
    invoke-virtual {v13, v11, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 1404
    .line 1405
    .line 1406
    :cond_4
    :goto_3
    add-int/lit8 v8, v10, 0x3

    .line 1407
    .line 1408
    goto/16 :goto_0

    .line 1409
    .line 1410
    :cond_5
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 1411
    .line 1412
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1413
    .line 1414
    .line 1415
    move-object v0, v1

    .line 1416
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1417
    .line 1418
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 1419
    .line 1420
    invoke-virtual {v0, v2}, Lcom/google/crypto/tink/shaded/protobuf/c1;->d(Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 1421
    .line 1422
    .line 1423
    return-void

    .line 1424
    nop

    .line 1425
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final a(Ljava/lang/Object;)V
    .locals 7

    .line 1
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->i:I

    .line 2
    .line 3
    :goto_0
    const/4 v1, 0x0

    .line 4
    iget-object v2, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->h:[I

    .line 5
    .line 6
    iget v3, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->j:I

    .line 7
    .line 8
    if-ge v0, v3, :cond_1

    .line 9
    .line 10
    aget v2, v2, v0

    .line 11
    .line 12
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    const v3, 0xfffff

    .line 17
    .line 18
    .line 19
    and-int/2addr v2, v3

    .line 20
    int-to-long v2, v2

    .line 21
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 22
    .line 23
    invoke-virtual {v4, p1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    if-nez v4, :cond_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    iget-object v5, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 31
    .line 32
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 33
    .line 34
    .line 35
    move-object v5, v4

    .line 36
    check-cast v5, Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 37
    .line 38
    iput-boolean v1, v5, Lcom/google/crypto/tink/shaded/protobuf/m0;->d:Z

    .line 39
    .line 40
    invoke-static {p1, v2, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    :goto_1
    add-int/lit8 v0, v0, 0x1

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    array-length v0, v2

    .line 47
    :goto_2
    if-ge v3, v0, :cond_2

    .line 48
    .line 49
    aget v4, v2, v3

    .line 50
    .line 51
    int-to-long v4, v4

    .line 52
    iget-object v6, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->l:Lcom/google/crypto/tink/shaded/protobuf/j0;

    .line 53
    .line 54
    invoke-virtual {v6, v4, v5, p1}, Lcom/google/crypto/tink/shaded/protobuf/j0;->a(JLjava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    add-int/lit8 v3, v3, 0x1

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_2
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 66
    .line 67
    iget-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 68
    .line 69
    iput-boolean v1, p0, Lcom/google/crypto/tink/shaded/protobuf/c1;->e:Z

    .line 70
    .line 71
    return-void
.end method

.method public final b(Ljava/lang/Object;)Z
    .locals 14

    .line 1
    const/4 v0, -0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    move v2, v1

    .line 4
    move v3, v2

    .line 5
    :goto_0
    iget v4, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->i:I

    .line 6
    .line 7
    const/4 v5, 0x1

    .line 8
    if-ge v2, v4, :cond_f

    .line 9
    .line 10
    iget-object v4, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->h:[I

    .line 11
    .line 12
    aget v4, v4, v2

    .line 13
    .line 14
    iget-object v6, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 15
    .line 16
    aget v7, v6, v4

    .line 17
    .line 18
    invoke-virtual {p0, v4}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 19
    .line 20
    .line 21
    move-result v8

    .line 22
    iget-boolean v9, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->g:Z

    .line 23
    .line 24
    const v10, 0xfffff

    .line 25
    .line 26
    .line 27
    if-nez v9, :cond_0

    .line 28
    .line 29
    add-int/lit8 v11, v4, 0x2

    .line 30
    .line 31
    aget v6, v6, v11

    .line 32
    .line 33
    and-int v11, v6, v10

    .line 34
    .line 35
    ushr-int/lit8 v6, v6, 0x14

    .line 36
    .line 37
    shl-int v6, v5, v6

    .line 38
    .line 39
    if-eq v11, v0, :cond_1

    .line 40
    .line 41
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 42
    .line 43
    int-to-long v12, v11

    .line 44
    invoke-virtual {v0, p1, v12, v13}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    move v0, v11

    .line 49
    goto :goto_1

    .line 50
    :cond_0
    move v6, v1

    .line 51
    :cond_1
    :goto_1
    const/high16 v11, 0x10000000

    .line 52
    .line 53
    and-int/2addr v11, v8

    .line 54
    if-eqz v11, :cond_4

    .line 55
    .line 56
    if-eqz v9, :cond_2

    .line 57
    .line 58
    invoke-virtual {p0, v4, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v11

    .line 62
    goto :goto_2

    .line 63
    :cond_2
    and-int v11, v3, v6

    .line 64
    .line 65
    if-eqz v11, :cond_3

    .line 66
    .line 67
    move v11, v5

    .line 68
    goto :goto_2

    .line 69
    :cond_3
    move v11, v1

    .line 70
    :goto_2
    if-nez v11, :cond_4

    .line 71
    .line 72
    goto/16 :goto_5

    .line 73
    .line 74
    :cond_4
    invoke-static {v8}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 75
    .line 76
    .line 77
    move-result v11

    .line 78
    const/16 v12, 0x9

    .line 79
    .line 80
    if-eq v11, v12, :cond_b

    .line 81
    .line 82
    const/16 v12, 0x11

    .line 83
    .line 84
    if-eq v11, v12, :cond_b

    .line 85
    .line 86
    const/16 v5, 0x1b

    .line 87
    .line 88
    if-eq v11, v5, :cond_8

    .line 89
    .line 90
    const/16 v5, 0x3c

    .line 91
    .line 92
    if-eq v11, v5, :cond_7

    .line 93
    .line 94
    const/16 v5, 0x44

    .line 95
    .line 96
    if-eq v11, v5, :cond_7

    .line 97
    .line 98
    const/16 v5, 0x31

    .line 99
    .line 100
    if-eq v11, v5, :cond_8

    .line 101
    .line 102
    const/16 v5, 0x32

    .line 103
    .line 104
    if-eq v11, v5, :cond_5

    .line 105
    .line 106
    goto/16 :goto_6

    .line 107
    .line 108
    :cond_5
    and-int v5, v8, v10

    .line 109
    .line 110
    int-to-long v5, v5

    .line 111
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 112
    .line 113
    invoke-virtual {v7, p1, v5, v6}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v5

    .line 117
    iget-object v6, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 118
    .line 119
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 120
    .line 121
    .line 122
    check-cast v5, Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 123
    .line 124
    invoke-virtual {v5}, Ljava/util/HashMap;->isEmpty()Z

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    if-eqz v5, :cond_6

    .line 129
    .line 130
    goto/16 :goto_6

    .line 131
    .line 132
    :cond_6
    invoke-virtual {p0, v4}, Lcom/google/crypto/tink/shaded/protobuf/r0;->n(I)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-static {p0}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    const/4 p0, 0x0

    .line 140
    throw p0

    .line 141
    :cond_7
    invoke-virtual {p0, v7, p1, v4}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 142
    .line 143
    .line 144
    move-result v5

    .line 145
    if-eqz v5, :cond_e

    .line 146
    .line 147
    invoke-virtual {p0, v4}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 148
    .line 149
    .line 150
    move-result-object v4

    .line 151
    and-int v5, v8, v10

    .line 152
    .line 153
    int-to-long v5, v5

    .line 154
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 155
    .line 156
    invoke-virtual {v7, p1, v5, v6}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v5

    .line 160
    invoke-interface {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/a1;->b(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v4

    .line 164
    if-nez v4, :cond_e

    .line 165
    .line 166
    goto :goto_5

    .line 167
    :cond_8
    and-int v5, v8, v10

    .line 168
    .line 169
    int-to-long v5, v5

    .line 170
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 171
    .line 172
    invoke-virtual {v7, p1, v5, v6}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v5

    .line 176
    check-cast v5, Ljava/util/List;

    .line 177
    .line 178
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 179
    .line 180
    .line 181
    move-result v6

    .line 182
    if-eqz v6, :cond_9

    .line 183
    .line 184
    goto :goto_6

    .line 185
    :cond_9
    invoke-virtual {p0, v4}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 186
    .line 187
    .line 188
    move-result-object v4

    .line 189
    move v6, v1

    .line 190
    :goto_3
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 191
    .line 192
    .line 193
    move-result v7

    .line 194
    if-ge v6, v7, :cond_e

    .line 195
    .line 196
    invoke-interface {v5, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v7

    .line 200
    invoke-interface {v4, v7}, Lcom/google/crypto/tink/shaded/protobuf/a1;->b(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v7

    .line 204
    if-nez v7, :cond_a

    .line 205
    .line 206
    goto :goto_5

    .line 207
    :cond_a
    add-int/lit8 v6, v6, 0x1

    .line 208
    .line 209
    goto :goto_3

    .line 210
    :cond_b
    if-eqz v9, :cond_c

    .line 211
    .line 212
    invoke-virtual {p0, v4, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    move-result v5

    .line 216
    goto :goto_4

    .line 217
    :cond_c
    and-int/2addr v6, v3

    .line 218
    if-eqz v6, :cond_d

    .line 219
    .line 220
    goto :goto_4

    .line 221
    :cond_d
    move v5, v1

    .line 222
    :goto_4
    if-eqz v5, :cond_e

    .line 223
    .line 224
    invoke-virtual {p0, v4}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 225
    .line 226
    .line 227
    move-result-object v4

    .line 228
    and-int v5, v8, v10

    .line 229
    .line 230
    int-to-long v5, v5

    .line 231
    sget-object v7, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 232
    .line 233
    invoke-virtual {v7, p1, v5, v6}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v5

    .line 237
    invoke-interface {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/a1;->b(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result v4

    .line 241
    if-nez v4, :cond_e

    .line 242
    .line 243
    :goto_5
    return v1

    .line 244
    :cond_e
    :goto_6
    add-int/lit8 v2, v2, 0x1

    .line 245
    .line 246
    goto/16 :goto_0

    .line 247
    .line 248
    :cond_f
    return v5
.end method

.method public final c()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->k:Lcom/google/crypto/tink/shaded/protobuf/t0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->e:Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 7
    .line 8
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final d(Ljava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v3, v2, Lcom/google/crypto/tink/shaded/protobuf/m;->a:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/k;

    .line 13
    .line 14
    iget-boolean v4, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->g:Z

    .line 15
    .line 16
    if-eqz v4, :cond_3

    .line 17
    .line 18
    iget-object v4, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 19
    .line 20
    array-length v5, v4

    .line 21
    const/4 v6, 0x0

    .line 22
    move v7, v6

    .line 23
    :goto_0
    if-ge v7, v5, :cond_2

    .line 24
    .line 25
    invoke-virtual {v0, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 26
    .line 27
    .line 28
    move-result v8

    .line 29
    aget v9, v4, v7

    .line 30
    .line 31
    invoke-static {v8}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 32
    .line 33
    .line 34
    move-result v10

    .line 35
    const/16 v11, 0x3f

    .line 36
    .line 37
    const/4 v12, 0x1

    .line 38
    const v13, 0xfffff

    .line 39
    .line 40
    .line 41
    packed-switch v10, :pswitch_data_0

    .line 42
    .line 43
    .line 44
    goto/16 :goto_1

    .line 45
    .line 46
    :pswitch_0
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 47
    .line 48
    .line 49
    move-result v10

    .line 50
    if-eqz v10, :cond_1

    .line 51
    .line 52
    and-int/2addr v8, v13

    .line 53
    int-to-long v10, v8

    .line 54
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 55
    .line 56
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v8

    .line 60
    invoke-virtual {v0, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 61
    .line 62
    .line 63
    move-result-object v10

    .line 64
    invoke-virtual {v2, v9, v8, v10}, Lcom/google/crypto/tink/shaded/protobuf/m;->b(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 65
    .line 66
    .line 67
    goto/16 :goto_1

    .line 68
    .line 69
    :pswitch_1
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 70
    .line 71
    .line 72
    move-result v10

    .line 73
    if-eqz v10, :cond_1

    .line 74
    .line 75
    and-int/2addr v8, v13

    .line 76
    int-to-long v13, v8

    .line 77
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 78
    .line 79
    .line 80
    move-result-wide v13

    .line 81
    shl-long v15, v13, v12

    .line 82
    .line 83
    shr-long v10, v13, v11

    .line 84
    .line 85
    xor-long/2addr v10, v15

    .line 86
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 87
    .line 88
    .line 89
    goto/16 :goto_1

    .line 90
    .line 91
    :pswitch_2
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 92
    .line 93
    .line 94
    move-result v10

    .line 95
    if-eqz v10, :cond_1

    .line 96
    .line 97
    and-int/2addr v8, v13

    .line 98
    int-to-long v10, v8

    .line 99
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 100
    .line 101
    .line 102
    move-result v8

    .line 103
    shl-int/lit8 v10, v8, 0x1

    .line 104
    .line 105
    shr-int/lit8 v8, v8, 0x1f

    .line 106
    .line 107
    xor-int/2addr v8, v10

    .line 108
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 112
    .line 113
    .line 114
    goto/16 :goto_1

    .line 115
    .line 116
    :pswitch_3
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 117
    .line 118
    .line 119
    move-result v10

    .line 120
    if-eqz v10, :cond_1

    .line 121
    .line 122
    and-int/2addr v8, v13

    .line 123
    int-to-long v10, v8

    .line 124
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 125
    .line 126
    .line 127
    move-result-wide v10

    .line 128
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 129
    .line 130
    .line 131
    goto/16 :goto_1

    .line 132
    .line 133
    :pswitch_4
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 134
    .line 135
    .line 136
    move-result v10

    .line 137
    if-eqz v10, :cond_1

    .line 138
    .line 139
    and-int/2addr v8, v13

    .line 140
    int-to-long v10, v8

    .line 141
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 142
    .line 143
    .line 144
    move-result v8

    .line 145
    invoke-virtual {v3, v9, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 146
    .line 147
    .line 148
    goto/16 :goto_1

    .line 149
    .line 150
    :pswitch_5
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 151
    .line 152
    .line 153
    move-result v10

    .line 154
    if-eqz v10, :cond_1

    .line 155
    .line 156
    and-int/2addr v8, v13

    .line 157
    int-to-long v10, v8

    .line 158
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 159
    .line 160
    .line 161
    move-result v8

    .line 162
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->P(I)V

    .line 166
    .line 167
    .line 168
    goto/16 :goto_1

    .line 169
    .line 170
    :pswitch_6
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 171
    .line 172
    .line 173
    move-result v10

    .line 174
    if-eqz v10, :cond_1

    .line 175
    .line 176
    and-int/2addr v8, v13

    .line 177
    int-to-long v10, v8

    .line 178
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 179
    .line 180
    .line 181
    move-result v8

    .line 182
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 186
    .line 187
    .line 188
    goto/16 :goto_1

    .line 189
    .line 190
    :pswitch_7
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 191
    .line 192
    .line 193
    move-result v10

    .line 194
    if-eqz v10, :cond_1

    .line 195
    .line 196
    and-int/2addr v8, v13

    .line 197
    int-to-long v10, v8

    .line 198
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 199
    .line 200
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v8

    .line 204
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 205
    .line 206
    invoke-virtual {v2, v9, v8}, Lcom/google/crypto/tink/shaded/protobuf/m;->a(ILcom/google/crypto/tink/shaded/protobuf/i;)V

    .line 207
    .line 208
    .line 209
    goto/16 :goto_1

    .line 210
    .line 211
    :pswitch_8
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 212
    .line 213
    .line 214
    move-result v10

    .line 215
    if-eqz v10, :cond_1

    .line 216
    .line 217
    and-int/2addr v8, v13

    .line 218
    int-to-long v10, v8

    .line 219
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 220
    .line 221
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v8

    .line 225
    invoke-virtual {v0, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 226
    .line 227
    .line 228
    move-result-object v10

    .line 229
    invoke-virtual {v2, v9, v8, v10}, Lcom/google/crypto/tink/shaded/protobuf/m;->c(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 230
    .line 231
    .line 232
    goto/16 :goto_1

    .line 233
    .line 234
    :pswitch_9
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 235
    .line 236
    .line 237
    move-result v10

    .line 238
    if-eqz v10, :cond_1

    .line 239
    .line 240
    and-int/2addr v8, v13

    .line 241
    int-to-long v10, v8

    .line 242
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 243
    .line 244
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v8

    .line 248
    invoke-static {v9, v8, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->Q(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 249
    .line 250
    .line 251
    goto/16 :goto_1

    .line 252
    .line 253
    :pswitch_a
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 254
    .line 255
    .line 256
    move-result v10

    .line 257
    if-eqz v10, :cond_1

    .line 258
    .line 259
    and-int/2addr v8, v13

    .line 260
    int-to-long v10, v8

    .line 261
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 262
    .line 263
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v8

    .line 267
    check-cast v8, Ljava/lang/Boolean;

    .line 268
    .line 269
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 270
    .line 271
    .line 272
    move-result v8

    .line 273
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 274
    .line 275
    .line 276
    int-to-byte v8, v8

    .line 277
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->J(B)V

    .line 278
    .line 279
    .line 280
    goto/16 :goto_1

    .line 281
    .line 282
    :pswitch_b
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 283
    .line 284
    .line 285
    move-result v10

    .line 286
    if-eqz v10, :cond_1

    .line 287
    .line 288
    and-int/2addr v8, v13

    .line 289
    int-to-long v10, v8

    .line 290
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 291
    .line 292
    .line 293
    move-result v8

    .line 294
    invoke-virtual {v3, v9, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 295
    .line 296
    .line 297
    goto/16 :goto_1

    .line 298
    .line 299
    :pswitch_c
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 300
    .line 301
    .line 302
    move-result v10

    .line 303
    if-eqz v10, :cond_1

    .line 304
    .line 305
    and-int/2addr v8, v13

    .line 306
    int-to-long v10, v8

    .line 307
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 308
    .line 309
    .line 310
    move-result-wide v10

    .line 311
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 312
    .line 313
    .line 314
    goto/16 :goto_1

    .line 315
    .line 316
    :pswitch_d
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 317
    .line 318
    .line 319
    move-result v10

    .line 320
    if-eqz v10, :cond_1

    .line 321
    .line 322
    and-int/2addr v8, v13

    .line 323
    int-to-long v10, v8

    .line 324
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 325
    .line 326
    .line 327
    move-result v8

    .line 328
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->P(I)V

    .line 332
    .line 333
    .line 334
    goto/16 :goto_1

    .line 335
    .line 336
    :pswitch_e
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 337
    .line 338
    .line 339
    move-result v10

    .line 340
    if-eqz v10, :cond_1

    .line 341
    .line 342
    and-int/2addr v8, v13

    .line 343
    int-to-long v10, v8

    .line 344
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 345
    .line 346
    .line 347
    move-result-wide v10

    .line 348
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 349
    .line 350
    .line 351
    goto/16 :goto_1

    .line 352
    .line 353
    :pswitch_f
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 354
    .line 355
    .line 356
    move-result v10

    .line 357
    if-eqz v10, :cond_1

    .line 358
    .line 359
    and-int/2addr v8, v13

    .line 360
    int-to-long v10, v8

    .line 361
    invoke-static {v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 362
    .line 363
    .line 364
    move-result-wide v10

    .line 365
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 366
    .line 367
    .line 368
    goto/16 :goto_1

    .line 369
    .line 370
    :pswitch_10
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 371
    .line 372
    .line 373
    move-result v10

    .line 374
    if-eqz v10, :cond_1

    .line 375
    .line 376
    and-int/2addr v8, v13

    .line 377
    int-to-long v10, v8

    .line 378
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 379
    .line 380
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    move-result-object v8

    .line 384
    check-cast v8, Ljava/lang/Float;

    .line 385
    .line 386
    invoke-virtual {v8}, Ljava/lang/Float;->floatValue()F

    .line 387
    .line 388
    .line 389
    move-result v8

    .line 390
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 391
    .line 392
    .line 393
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 394
    .line 395
    .line 396
    move-result v8

    .line 397
    invoke-virtual {v3, v9, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 398
    .line 399
    .line 400
    goto/16 :goto_1

    .line 401
    .line 402
    :pswitch_11
    invoke-virtual {v0, v9, v1, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 403
    .line 404
    .line 405
    move-result v10

    .line 406
    if-eqz v10, :cond_1

    .line 407
    .line 408
    and-int/2addr v8, v13

    .line 409
    int-to-long v10, v8

    .line 410
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 411
    .line 412
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 413
    .line 414
    .line 415
    move-result-object v8

    .line 416
    check-cast v8, Ljava/lang/Double;

    .line 417
    .line 418
    invoke-virtual {v8}, Ljava/lang/Double;->doubleValue()D

    .line 419
    .line 420
    .line 421
    move-result-wide v10

    .line 422
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 423
    .line 424
    .line 425
    invoke-static {v10, v11}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 426
    .line 427
    .line 428
    move-result-wide v10

    .line 429
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 430
    .line 431
    .line 432
    goto/16 :goto_1

    .line 433
    .line 434
    :pswitch_12
    and-int/2addr v8, v13

    .line 435
    int-to-long v8, v8

    .line 436
    sget-object v10, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 437
    .line 438
    invoke-virtual {v10, v1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 439
    .line 440
    .line 441
    move-result-object v8

    .line 442
    if-nez v8, :cond_0

    .line 443
    .line 444
    goto/16 :goto_1

    .line 445
    .line 446
    :cond_0
    invoke-virtual {v0, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->n(I)Ljava/lang/Object;

    .line 447
    .line 448
    .line 449
    move-result-object v1

    .line 450
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 451
    .line 452
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 453
    .line 454
    .line 455
    invoke-static {v1}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 456
    .line 457
    .line 458
    const/4 v0, 0x0

    .line 459
    throw v0

    .line 460
    :pswitch_13
    aget v9, v4, v7

    .line 461
    .line 462
    and-int/2addr v8, v13

    .line 463
    int-to-long v10, v8

    .line 464
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 465
    .line 466
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 467
    .line 468
    .line 469
    move-result-object v8

    .line 470
    check-cast v8, Ljava/util/List;

    .line 471
    .line 472
    invoke-virtual {v0, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 473
    .line 474
    .line 475
    move-result-object v10

    .line 476
    invoke-static {v9, v8, v2, v10}, Lcom/google/crypto/tink/shaded/protobuf/b1;->G(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 477
    .line 478
    .line 479
    goto/16 :goto_1

    .line 480
    .line 481
    :pswitch_14
    aget v9, v4, v7

    .line 482
    .line 483
    and-int/2addr v8, v13

    .line 484
    int-to-long v10, v8

    .line 485
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 486
    .line 487
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 488
    .line 489
    .line 490
    move-result-object v8

    .line 491
    check-cast v8, Ljava/util/List;

    .line 492
    .line 493
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->N(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 494
    .line 495
    .line 496
    goto/16 :goto_1

    .line 497
    .line 498
    :pswitch_15
    aget v9, v4, v7

    .line 499
    .line 500
    and-int/2addr v8, v13

    .line 501
    int-to-long v10, v8

    .line 502
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 503
    .line 504
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    move-result-object v8

    .line 508
    check-cast v8, Ljava/util/List;

    .line 509
    .line 510
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->M(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 511
    .line 512
    .line 513
    goto/16 :goto_1

    .line 514
    .line 515
    :pswitch_16
    aget v9, v4, v7

    .line 516
    .line 517
    and-int/2addr v8, v13

    .line 518
    int-to-long v10, v8

    .line 519
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 520
    .line 521
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 522
    .line 523
    .line 524
    move-result-object v8

    .line 525
    check-cast v8, Ljava/util/List;

    .line 526
    .line 527
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->L(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 528
    .line 529
    .line 530
    goto/16 :goto_1

    .line 531
    .line 532
    :pswitch_17
    aget v9, v4, v7

    .line 533
    .line 534
    and-int/2addr v8, v13

    .line 535
    int-to-long v10, v8

    .line 536
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 537
    .line 538
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 539
    .line 540
    .line 541
    move-result-object v8

    .line 542
    check-cast v8, Ljava/util/List;

    .line 543
    .line 544
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->K(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 545
    .line 546
    .line 547
    goto/16 :goto_1

    .line 548
    .line 549
    :pswitch_18
    aget v9, v4, v7

    .line 550
    .line 551
    and-int/2addr v8, v13

    .line 552
    int-to-long v10, v8

    .line 553
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 554
    .line 555
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 556
    .line 557
    .line 558
    move-result-object v8

    .line 559
    check-cast v8, Ljava/util/List;

    .line 560
    .line 561
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->C(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 562
    .line 563
    .line 564
    goto/16 :goto_1

    .line 565
    .line 566
    :pswitch_19
    aget v9, v4, v7

    .line 567
    .line 568
    and-int/2addr v8, v13

    .line 569
    int-to-long v10, v8

    .line 570
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 571
    .line 572
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 573
    .line 574
    .line 575
    move-result-object v8

    .line 576
    check-cast v8, Ljava/util/List;

    .line 577
    .line 578
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->P(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 579
    .line 580
    .line 581
    goto/16 :goto_1

    .line 582
    .line 583
    :pswitch_1a
    aget v9, v4, v7

    .line 584
    .line 585
    and-int/2addr v8, v13

    .line 586
    int-to-long v10, v8

    .line 587
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 588
    .line 589
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 590
    .line 591
    .line 592
    move-result-object v8

    .line 593
    check-cast v8, Ljava/util/List;

    .line 594
    .line 595
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->z(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 596
    .line 597
    .line 598
    goto/16 :goto_1

    .line 599
    .line 600
    :pswitch_1b
    aget v9, v4, v7

    .line 601
    .line 602
    and-int/2addr v8, v13

    .line 603
    int-to-long v10, v8

    .line 604
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 605
    .line 606
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 607
    .line 608
    .line 609
    move-result-object v8

    .line 610
    check-cast v8, Ljava/util/List;

    .line 611
    .line 612
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->D(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 613
    .line 614
    .line 615
    goto/16 :goto_1

    .line 616
    .line 617
    :pswitch_1c
    aget v9, v4, v7

    .line 618
    .line 619
    and-int/2addr v8, v13

    .line 620
    int-to-long v10, v8

    .line 621
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 622
    .line 623
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 624
    .line 625
    .line 626
    move-result-object v8

    .line 627
    check-cast v8, Ljava/util/List;

    .line 628
    .line 629
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->E(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 630
    .line 631
    .line 632
    goto/16 :goto_1

    .line 633
    .line 634
    :pswitch_1d
    aget v9, v4, v7

    .line 635
    .line 636
    and-int/2addr v8, v13

    .line 637
    int-to-long v10, v8

    .line 638
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 639
    .line 640
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 641
    .line 642
    .line 643
    move-result-object v8

    .line 644
    check-cast v8, Ljava/util/List;

    .line 645
    .line 646
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->H(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 647
    .line 648
    .line 649
    goto/16 :goto_1

    .line 650
    .line 651
    :pswitch_1e
    aget v9, v4, v7

    .line 652
    .line 653
    and-int/2addr v8, v13

    .line 654
    int-to-long v10, v8

    .line 655
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 656
    .line 657
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 658
    .line 659
    .line 660
    move-result-object v8

    .line 661
    check-cast v8, Ljava/util/List;

    .line 662
    .line 663
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->Q(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 664
    .line 665
    .line 666
    goto/16 :goto_1

    .line 667
    .line 668
    :pswitch_1f
    aget v9, v4, v7

    .line 669
    .line 670
    and-int/2addr v8, v13

    .line 671
    int-to-long v10, v8

    .line 672
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 673
    .line 674
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 675
    .line 676
    .line 677
    move-result-object v8

    .line 678
    check-cast v8, Ljava/util/List;

    .line 679
    .line 680
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->I(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 681
    .line 682
    .line 683
    goto/16 :goto_1

    .line 684
    .line 685
    :pswitch_20
    aget v9, v4, v7

    .line 686
    .line 687
    and-int/2addr v8, v13

    .line 688
    int-to-long v10, v8

    .line 689
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 690
    .line 691
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 692
    .line 693
    .line 694
    move-result-object v8

    .line 695
    check-cast v8, Ljava/util/List;

    .line 696
    .line 697
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->F(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 698
    .line 699
    .line 700
    goto/16 :goto_1

    .line 701
    .line 702
    :pswitch_21
    aget v9, v4, v7

    .line 703
    .line 704
    and-int/2addr v8, v13

    .line 705
    int-to-long v10, v8

    .line 706
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 707
    .line 708
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 709
    .line 710
    .line 711
    move-result-object v8

    .line 712
    check-cast v8, Ljava/util/List;

    .line 713
    .line 714
    invoke-static {v9, v8, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/b1;->B(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 715
    .line 716
    .line 717
    goto/16 :goto_1

    .line 718
    .line 719
    :pswitch_22
    aget v9, v4, v7

    .line 720
    .line 721
    and-int/2addr v8, v13

    .line 722
    int-to-long v10, v8

    .line 723
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 724
    .line 725
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 726
    .line 727
    .line 728
    move-result-object v8

    .line 729
    check-cast v8, Ljava/util/List;

    .line 730
    .line 731
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->N(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 732
    .line 733
    .line 734
    goto/16 :goto_1

    .line 735
    .line 736
    :pswitch_23
    aget v9, v4, v7

    .line 737
    .line 738
    and-int/2addr v8, v13

    .line 739
    int-to-long v10, v8

    .line 740
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 741
    .line 742
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 743
    .line 744
    .line 745
    move-result-object v8

    .line 746
    check-cast v8, Ljava/util/List;

    .line 747
    .line 748
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->M(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 749
    .line 750
    .line 751
    goto/16 :goto_1

    .line 752
    .line 753
    :pswitch_24
    aget v9, v4, v7

    .line 754
    .line 755
    and-int/2addr v8, v13

    .line 756
    int-to-long v10, v8

    .line 757
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 758
    .line 759
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 760
    .line 761
    .line 762
    move-result-object v8

    .line 763
    check-cast v8, Ljava/util/List;

    .line 764
    .line 765
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->L(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 766
    .line 767
    .line 768
    goto/16 :goto_1

    .line 769
    .line 770
    :pswitch_25
    aget v9, v4, v7

    .line 771
    .line 772
    and-int/2addr v8, v13

    .line 773
    int-to-long v10, v8

    .line 774
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 775
    .line 776
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 777
    .line 778
    .line 779
    move-result-object v8

    .line 780
    check-cast v8, Ljava/util/List;

    .line 781
    .line 782
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->K(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 783
    .line 784
    .line 785
    goto/16 :goto_1

    .line 786
    .line 787
    :pswitch_26
    aget v9, v4, v7

    .line 788
    .line 789
    and-int/2addr v8, v13

    .line 790
    int-to-long v10, v8

    .line 791
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 792
    .line 793
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 794
    .line 795
    .line 796
    move-result-object v8

    .line 797
    check-cast v8, Ljava/util/List;

    .line 798
    .line 799
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->C(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 800
    .line 801
    .line 802
    goto/16 :goto_1

    .line 803
    .line 804
    :pswitch_27
    aget v9, v4, v7

    .line 805
    .line 806
    and-int/2addr v8, v13

    .line 807
    int-to-long v10, v8

    .line 808
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 809
    .line 810
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 811
    .line 812
    .line 813
    move-result-object v8

    .line 814
    check-cast v8, Ljava/util/List;

    .line 815
    .line 816
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->P(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 817
    .line 818
    .line 819
    goto/16 :goto_1

    .line 820
    .line 821
    :pswitch_28
    aget v9, v4, v7

    .line 822
    .line 823
    and-int/2addr v8, v13

    .line 824
    int-to-long v10, v8

    .line 825
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 826
    .line 827
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 828
    .line 829
    .line 830
    move-result-object v8

    .line 831
    check-cast v8, Ljava/util/List;

    .line 832
    .line 833
    invoke-static {v9, v8, v2}, Lcom/google/crypto/tink/shaded/protobuf/b1;->A(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 834
    .line 835
    .line 836
    goto/16 :goto_1

    .line 837
    .line 838
    :pswitch_29
    aget v9, v4, v7

    .line 839
    .line 840
    and-int/2addr v8, v13

    .line 841
    int-to-long v10, v8

    .line 842
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 843
    .line 844
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 845
    .line 846
    .line 847
    move-result-object v8

    .line 848
    check-cast v8, Ljava/util/List;

    .line 849
    .line 850
    invoke-virtual {v0, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 851
    .line 852
    .line 853
    move-result-object v10

    .line 854
    invoke-static {v9, v8, v2, v10}, Lcom/google/crypto/tink/shaded/protobuf/b1;->J(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 855
    .line 856
    .line 857
    goto/16 :goto_1

    .line 858
    .line 859
    :pswitch_2a
    aget v9, v4, v7

    .line 860
    .line 861
    and-int/2addr v8, v13

    .line 862
    int-to-long v10, v8

    .line 863
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 864
    .line 865
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 866
    .line 867
    .line 868
    move-result-object v8

    .line 869
    check-cast v8, Ljava/util/List;

    .line 870
    .line 871
    invoke-static {v9, v8, v2}, Lcom/google/crypto/tink/shaded/protobuf/b1;->O(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 872
    .line 873
    .line 874
    goto/16 :goto_1

    .line 875
    .line 876
    :pswitch_2b
    aget v9, v4, v7

    .line 877
    .line 878
    and-int/2addr v8, v13

    .line 879
    int-to-long v10, v8

    .line 880
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 881
    .line 882
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 883
    .line 884
    .line 885
    move-result-object v8

    .line 886
    check-cast v8, Ljava/util/List;

    .line 887
    .line 888
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->z(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 889
    .line 890
    .line 891
    goto/16 :goto_1

    .line 892
    .line 893
    :pswitch_2c
    aget v9, v4, v7

    .line 894
    .line 895
    and-int/2addr v8, v13

    .line 896
    int-to-long v10, v8

    .line 897
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 898
    .line 899
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 900
    .line 901
    .line 902
    move-result-object v8

    .line 903
    check-cast v8, Ljava/util/List;

    .line 904
    .line 905
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->D(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 906
    .line 907
    .line 908
    goto/16 :goto_1

    .line 909
    .line 910
    :pswitch_2d
    aget v9, v4, v7

    .line 911
    .line 912
    and-int/2addr v8, v13

    .line 913
    int-to-long v10, v8

    .line 914
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 915
    .line 916
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 917
    .line 918
    .line 919
    move-result-object v8

    .line 920
    check-cast v8, Ljava/util/List;

    .line 921
    .line 922
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->E(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 923
    .line 924
    .line 925
    goto/16 :goto_1

    .line 926
    .line 927
    :pswitch_2e
    aget v9, v4, v7

    .line 928
    .line 929
    and-int/2addr v8, v13

    .line 930
    int-to-long v10, v8

    .line 931
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 932
    .line 933
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 934
    .line 935
    .line 936
    move-result-object v8

    .line 937
    check-cast v8, Ljava/util/List;

    .line 938
    .line 939
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->H(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 940
    .line 941
    .line 942
    goto/16 :goto_1

    .line 943
    .line 944
    :pswitch_2f
    aget v9, v4, v7

    .line 945
    .line 946
    and-int/2addr v8, v13

    .line 947
    int-to-long v10, v8

    .line 948
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 949
    .line 950
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 951
    .line 952
    .line 953
    move-result-object v8

    .line 954
    check-cast v8, Ljava/util/List;

    .line 955
    .line 956
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->Q(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 957
    .line 958
    .line 959
    goto/16 :goto_1

    .line 960
    .line 961
    :pswitch_30
    aget v9, v4, v7

    .line 962
    .line 963
    and-int/2addr v8, v13

    .line 964
    int-to-long v10, v8

    .line 965
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 966
    .line 967
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 968
    .line 969
    .line 970
    move-result-object v8

    .line 971
    check-cast v8, Ljava/util/List;

    .line 972
    .line 973
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->I(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 974
    .line 975
    .line 976
    goto/16 :goto_1

    .line 977
    .line 978
    :pswitch_31
    aget v9, v4, v7

    .line 979
    .line 980
    and-int/2addr v8, v13

    .line 981
    int-to-long v10, v8

    .line 982
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 983
    .line 984
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 985
    .line 986
    .line 987
    move-result-object v8

    .line 988
    check-cast v8, Ljava/util/List;

    .line 989
    .line 990
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->F(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 991
    .line 992
    .line 993
    goto/16 :goto_1

    .line 994
    .line 995
    :pswitch_32
    aget v9, v4, v7

    .line 996
    .line 997
    and-int/2addr v8, v13

    .line 998
    int-to-long v10, v8

    .line 999
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1000
    .line 1001
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v8

    .line 1005
    check-cast v8, Ljava/util/List;

    .line 1006
    .line 1007
    invoke-static {v9, v8, v2, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->B(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/m;Z)V

    .line 1008
    .line 1009
    .line 1010
    goto/16 :goto_1

    .line 1011
    .line 1012
    :pswitch_33
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1013
    .line 1014
    .line 1015
    move-result v10

    .line 1016
    if-eqz v10, :cond_1

    .line 1017
    .line 1018
    and-int/2addr v8, v13

    .line 1019
    int-to-long v10, v8

    .line 1020
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1021
    .line 1022
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1023
    .line 1024
    .line 1025
    move-result-object v8

    .line 1026
    invoke-virtual {v0, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v10

    .line 1030
    invoke-virtual {v2, v9, v8, v10}, Lcom/google/crypto/tink/shaded/protobuf/m;->b(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 1031
    .line 1032
    .line 1033
    goto/16 :goto_1

    .line 1034
    .line 1035
    :pswitch_34
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1036
    .line 1037
    .line 1038
    move-result v10

    .line 1039
    if-eqz v10, :cond_1

    .line 1040
    .line 1041
    and-int/2addr v8, v13

    .line 1042
    int-to-long v13, v8

    .line 1043
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1044
    .line 1045
    invoke-virtual {v8, v1, v13, v14}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 1046
    .line 1047
    .line 1048
    move-result-wide v13

    .line 1049
    shl-long v15, v13, v12

    .line 1050
    .line 1051
    shr-long v10, v13, v11

    .line 1052
    .line 1053
    xor-long/2addr v10, v15

    .line 1054
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 1055
    .line 1056
    .line 1057
    goto/16 :goto_1

    .line 1058
    .line 1059
    :pswitch_35
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1060
    .line 1061
    .line 1062
    move-result v10

    .line 1063
    if-eqz v10, :cond_1

    .line 1064
    .line 1065
    and-int/2addr v8, v13

    .line 1066
    int-to-long v10, v8

    .line 1067
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1068
    .line 1069
    invoke-virtual {v8, v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1070
    .line 1071
    .line 1072
    move-result v8

    .line 1073
    shl-int/lit8 v10, v8, 0x1

    .line 1074
    .line 1075
    shr-int/lit8 v8, v8, 0x1f

    .line 1076
    .line 1077
    xor-int/2addr v8, v10

    .line 1078
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1079
    .line 1080
    .line 1081
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 1082
    .line 1083
    .line 1084
    goto/16 :goto_1

    .line 1085
    .line 1086
    :pswitch_36
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1087
    .line 1088
    .line 1089
    move-result v10

    .line 1090
    if-eqz v10, :cond_1

    .line 1091
    .line 1092
    and-int/2addr v8, v13

    .line 1093
    int-to-long v10, v8

    .line 1094
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1095
    .line 1096
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 1097
    .line 1098
    .line 1099
    move-result-wide v10

    .line 1100
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 1101
    .line 1102
    .line 1103
    goto/16 :goto_1

    .line 1104
    .line 1105
    :pswitch_37
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1106
    .line 1107
    .line 1108
    move-result v10

    .line 1109
    if-eqz v10, :cond_1

    .line 1110
    .line 1111
    and-int/2addr v8, v13

    .line 1112
    int-to-long v10, v8

    .line 1113
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1114
    .line 1115
    invoke-virtual {v8, v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1116
    .line 1117
    .line 1118
    move-result v8

    .line 1119
    invoke-virtual {v3, v9, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 1120
    .line 1121
    .line 1122
    goto/16 :goto_1

    .line 1123
    .line 1124
    :pswitch_38
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1125
    .line 1126
    .line 1127
    move-result v10

    .line 1128
    if-eqz v10, :cond_1

    .line 1129
    .line 1130
    and-int/2addr v8, v13

    .line 1131
    int-to-long v10, v8

    .line 1132
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1133
    .line 1134
    invoke-virtual {v8, v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1135
    .line 1136
    .line 1137
    move-result v8

    .line 1138
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1139
    .line 1140
    .line 1141
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->P(I)V

    .line 1142
    .line 1143
    .line 1144
    goto/16 :goto_1

    .line 1145
    .line 1146
    :pswitch_39
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1147
    .line 1148
    .line 1149
    move-result v10

    .line 1150
    if-eqz v10, :cond_1

    .line 1151
    .line 1152
    and-int/2addr v8, v13

    .line 1153
    int-to-long v10, v8

    .line 1154
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1155
    .line 1156
    invoke-virtual {v8, v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1157
    .line 1158
    .line 1159
    move-result v8

    .line 1160
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1161
    .line 1162
    .line 1163
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->R(I)V

    .line 1164
    .line 1165
    .line 1166
    goto/16 :goto_1

    .line 1167
    .line 1168
    :pswitch_3a
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1169
    .line 1170
    .line 1171
    move-result v10

    .line 1172
    if-eqz v10, :cond_1

    .line 1173
    .line 1174
    and-int/2addr v8, v13

    .line 1175
    int-to-long v10, v8

    .line 1176
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1177
    .line 1178
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1179
    .line 1180
    .line 1181
    move-result-object v8

    .line 1182
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 1183
    .line 1184
    invoke-virtual {v2, v9, v8}, Lcom/google/crypto/tink/shaded/protobuf/m;->a(ILcom/google/crypto/tink/shaded/protobuf/i;)V

    .line 1185
    .line 1186
    .line 1187
    goto/16 :goto_1

    .line 1188
    .line 1189
    :pswitch_3b
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1190
    .line 1191
    .line 1192
    move-result v10

    .line 1193
    if-eqz v10, :cond_1

    .line 1194
    .line 1195
    and-int/2addr v8, v13

    .line 1196
    int-to-long v10, v8

    .line 1197
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1198
    .line 1199
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1200
    .line 1201
    .line 1202
    move-result-object v8

    .line 1203
    invoke-virtual {v0, v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v10

    .line 1207
    invoke-virtual {v2, v9, v8, v10}, Lcom/google/crypto/tink/shaded/protobuf/m;->c(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/a1;)V

    .line 1208
    .line 1209
    .line 1210
    goto/16 :goto_1

    .line 1211
    .line 1212
    :pswitch_3c
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1213
    .line 1214
    .line 1215
    move-result v10

    .line 1216
    if-eqz v10, :cond_1

    .line 1217
    .line 1218
    and-int/2addr v8, v13

    .line 1219
    int-to-long v10, v8

    .line 1220
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1221
    .line 1222
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1223
    .line 1224
    .line 1225
    move-result-object v8

    .line 1226
    invoke-static {v9, v8, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->Q(ILjava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 1227
    .line 1228
    .line 1229
    goto/16 :goto_1

    .line 1230
    .line 1231
    :pswitch_3d
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1232
    .line 1233
    .line 1234
    move-result v10

    .line 1235
    if-eqz v10, :cond_1

    .line 1236
    .line 1237
    and-int/2addr v8, v13

    .line 1238
    int-to-long v10, v8

    .line 1239
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1240
    .line 1241
    invoke-virtual {v8, v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->c(JLjava/lang/Object;)Z

    .line 1242
    .line 1243
    .line 1244
    move-result v8

    .line 1245
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1246
    .line 1247
    .line 1248
    int-to-byte v8, v8

    .line 1249
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->J(B)V

    .line 1250
    .line 1251
    .line 1252
    goto/16 :goto_1

    .line 1253
    .line 1254
    :pswitch_3e
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1255
    .line 1256
    .line 1257
    move-result v10

    .line 1258
    if-eqz v10, :cond_1

    .line 1259
    .line 1260
    and-int/2addr v8, v13

    .line 1261
    int-to-long v10, v8

    .line 1262
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1263
    .line 1264
    invoke-virtual {v8, v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1265
    .line 1266
    .line 1267
    move-result v8

    .line 1268
    invoke-virtual {v3, v9, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 1269
    .line 1270
    .line 1271
    goto/16 :goto_1

    .line 1272
    .line 1273
    :pswitch_3f
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1274
    .line 1275
    .line 1276
    move-result v10

    .line 1277
    if-eqz v10, :cond_1

    .line 1278
    .line 1279
    and-int/2addr v8, v13

    .line 1280
    int-to-long v10, v8

    .line 1281
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1282
    .line 1283
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 1284
    .line 1285
    .line 1286
    move-result-wide v10

    .line 1287
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 1288
    .line 1289
    .line 1290
    goto :goto_1

    .line 1291
    :pswitch_40
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1292
    .line 1293
    .line 1294
    move-result v10

    .line 1295
    if-eqz v10, :cond_1

    .line 1296
    .line 1297
    and-int/2addr v8, v13

    .line 1298
    int-to-long v10, v8

    .line 1299
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1300
    .line 1301
    invoke-virtual {v8, v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1302
    .line 1303
    .line 1304
    move-result v8

    .line 1305
    invoke-virtual {v3, v9, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->Q(II)V

    .line 1306
    .line 1307
    .line 1308
    invoke-virtual {v3, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->P(I)V

    .line 1309
    .line 1310
    .line 1311
    goto :goto_1

    .line 1312
    :pswitch_41
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1313
    .line 1314
    .line 1315
    move-result v10

    .line 1316
    if-eqz v10, :cond_1

    .line 1317
    .line 1318
    and-int/2addr v8, v13

    .line 1319
    int-to-long v10, v8

    .line 1320
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1321
    .line 1322
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 1323
    .line 1324
    .line 1325
    move-result-wide v10

    .line 1326
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 1327
    .line 1328
    .line 1329
    goto :goto_1

    .line 1330
    :pswitch_42
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1331
    .line 1332
    .line 1333
    move-result v10

    .line 1334
    if-eqz v10, :cond_1

    .line 1335
    .line 1336
    and-int/2addr v8, v13

    .line 1337
    int-to-long v10, v8

    .line 1338
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1339
    .line 1340
    invoke-virtual {v8, v1, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 1341
    .line 1342
    .line 1343
    move-result-wide v10

    .line 1344
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->S(IJ)V

    .line 1345
    .line 1346
    .line 1347
    goto :goto_1

    .line 1348
    :pswitch_43
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1349
    .line 1350
    .line 1351
    move-result v10

    .line 1352
    if-eqz v10, :cond_1

    .line 1353
    .line 1354
    and-int/2addr v8, v13

    .line 1355
    int-to-long v10, v8

    .line 1356
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1357
    .line 1358
    invoke-virtual {v8, v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->f(JLjava/lang/Object;)F

    .line 1359
    .line 1360
    .line 1361
    move-result v8

    .line 1362
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1363
    .line 1364
    .line 1365
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1366
    .line 1367
    .line 1368
    move-result v8

    .line 1369
    invoke-virtual {v3, v9, v8}, Lcom/google/crypto/tink/shaded/protobuf/k;->L(II)V

    .line 1370
    .line 1371
    .line 1372
    goto :goto_1

    .line 1373
    :pswitch_44
    invoke-virtual {v0, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1374
    .line 1375
    .line 1376
    move-result v10

    .line 1377
    if-eqz v10, :cond_1

    .line 1378
    .line 1379
    and-int/2addr v8, v13

    .line 1380
    int-to-long v10, v8

    .line 1381
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1382
    .line 1383
    invoke-virtual {v8, v10, v11, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->e(JLjava/lang/Object;)D

    .line 1384
    .line 1385
    .line 1386
    move-result-wide v10

    .line 1387
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1388
    .line 1389
    .line 1390
    invoke-static {v10, v11}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 1391
    .line 1392
    .line 1393
    move-result-wide v10

    .line 1394
    invoke-virtual {v3, v9, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->N(IJ)V

    .line 1395
    .line 1396
    .line 1397
    :cond_1
    :goto_1
    add-int/lit8 v7, v7, 0x3

    .line 1398
    .line 1399
    goto/16 :goto_0

    .line 1400
    .line 1401
    :cond_2
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 1402
    .line 1403
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1404
    .line 1405
    .line 1406
    move-object v0, v1

    .line 1407
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1408
    .line 1409
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 1410
    .line 1411
    invoke-virtual {v0, v2}, Lcom/google/crypto/tink/shaded/protobuf/c1;->d(Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 1412
    .line 1413
    .line 1414
    return-void

    .line 1415
    :cond_3
    invoke-virtual/range {p0 .. p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->P(Ljava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 1416
    .line 1417
    .line 1418
    return-void

    .line 1419
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final e(Ljava/lang/Object;[BIILcom/google/crypto/tink/shaded/protobuf/d;)V
    .locals 8

    .line 1
    iget-boolean v0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual/range {p0 .. p5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->F(Ljava/lang/Object;[BIILcom/google/crypto/tink/shaded/protobuf/d;)V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    const/4 v6, 0x0

    .line 10
    move-object v1, p0

    .line 11
    move-object v2, p1

    .line 12
    move-object v3, p2

    .line 13
    move v4, p3

    .line 14
    move v5, p4

    .line 15
    move-object v7, p5

    .line 16
    invoke-virtual/range {v1 .. v7}, Lcom/google/crypto/tink/shaded/protobuf/r0;->E(Ljava/lang/Object;[BIIILcom/google/crypto/tink/shaded/protobuf/d;)I

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public final f(Ljava/lang/Object;Landroidx/collection/h;Lcom/google/crypto/tink/shaded/protobuf/p;)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v4, p2

    .line 6
    .line 7
    move-object/from16 v6, p3

    .line 8
    .line 9
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    iget-object v7, v1, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 13
    .line 14
    iget-object v8, v1, Lcom/google/crypto/tink/shaded/protobuf/r0;->h:[I

    .line 15
    .line 16
    iget v9, v1, Lcom/google/crypto/tink/shaded/protobuf/r0;->j:I

    .line 17
    .line 18
    iget v10, v1, Lcom/google/crypto/tink/shaded/protobuf/r0;->i:I

    .line 19
    .line 20
    const/4 v12, 0x0

    .line 21
    :goto_0
    :try_start_0
    invoke-virtual {v4}, Landroidx/collection/h;->e()I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    iget v3, v1, Lcom/google/crypto/tink/shaded/protobuf/r0;->c:I

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    if-lt v0, v3, :cond_0

    .line 29
    .line 30
    iget v3, v1, Lcom/google/crypto/tink/shaded/protobuf/r0;->d:I

    .line 31
    .line 32
    if-gt v0, v3, :cond_0

    .line 33
    .line 34
    invoke-virtual {v1, v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->M(II)I

    .line 35
    .line 36
    .line 37
    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_6

    .line 38
    :goto_1
    move v13, v3

    .line 39
    goto :goto_3

    .line 40
    :goto_2
    move-object v6, v1

    .line 41
    move v1, v9

    .line 42
    move v15, v10

    .line 43
    move-object v10, v8

    .line 44
    goto/16 :goto_14

    .line 45
    .line 46
    :cond_0
    const/4 v3, -0x1

    .line 47
    goto :goto_1

    .line 48
    :goto_3
    sget-object v14, Lcom/google/crypto/tink/shaded/protobuf/c1;->f:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 49
    .line 50
    if-gez v13, :cond_7

    .line 51
    .line 52
    const v3, 0x7fffffff

    .line 53
    .line 54
    .line 55
    if-ne v0, v3, :cond_2

    .line 56
    .line 57
    :goto_4
    if-ge v10, v9, :cond_1

    .line 58
    .line 59
    aget v0, v8, v10

    .line 60
    .line 61
    invoke-virtual {v1, v0, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->l(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    add-int/lit8 v10, v10, 0x1

    .line 65
    .line 66
    goto :goto_4

    .line 67
    :cond_1
    if-eqz v12, :cond_13

    .line 68
    .line 69
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    goto/16 :goto_9

    .line 73
    .line 74
    :cond_2
    :try_start_1
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    if-nez v12, :cond_4

    .line 78
    .line 79
    move-object v0, v2

    .line 80
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 81
    .line 82
    iget-object v3, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 83
    .line 84
    if-ne v3, v14, :cond_3

    .line 85
    .line 86
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c1;->b()Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    iput-object v3, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 91
    .line 92
    :cond_3
    move-object v12, v3

    .line 93
    :cond_4
    invoke-static {v12, v4}, Lcom/google/crypto/tink/shaded/protobuf/d1;->a(Ljava/lang/Object;Landroidx/collection/h;)Z

    .line 94
    .line 95
    .line 96
    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_6

    .line 97
    if-eqz v0, :cond_5

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_5
    :goto_5
    if-ge v10, v9, :cond_6

    .line 101
    .line 102
    aget v0, v8, v10

    .line 103
    .line 104
    invoke-virtual {v1, v0, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->l(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    add-int/lit8 v10, v10, 0x1

    .line 108
    .line 109
    goto :goto_5

    .line 110
    :cond_6
    if-eqz v12, :cond_13

    .line 111
    .line 112
    goto :goto_9

    .line 113
    :cond_7
    :try_start_2
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 114
    .line 115
    .line 116
    move-result v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_6

    .line 117
    :try_start_3
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 118
    .line 119
    .line 120
    move-result v15
    :try_end_3
    .catch Lcom/google/crypto/tink/shaded/protobuf/c0; {:try_start_3 .. :try_end_3} :catch_5
    .catchall {:try_start_3 .. :try_end_3} :catchall_5

    .line 121
    const v16, 0xfffff

    .line 122
    .line 123
    .line 124
    const/16 v17, 0x0

    .line 125
    .line 126
    iget-object v11, v1, Lcom/google/crypto/tink/shaded/protobuf/r0;->l:Lcom/google/crypto/tink/shaded/protobuf/j0;

    .line 127
    .line 128
    packed-switch v15, :pswitch_data_0

    .line 129
    .line 130
    .line 131
    if-nez v12, :cond_8

    .line 132
    .line 133
    :try_start_4
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 134
    .line 135
    .line 136
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c1;->b()Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 137
    .line 138
    .line 139
    move-result-object v12

    .line 140
    goto :goto_7

    .line 141
    :catch_0
    move/from16 v18, v9

    .line 142
    .line 143
    move v15, v10

    .line 144
    :goto_6
    move-object v9, v6

    .line 145
    move-object v10, v8

    .line 146
    move-object v6, v1

    .line 147
    move-object v8, v4

    .line 148
    goto/16 :goto_10

    .line 149
    .line 150
    :cond_8
    :goto_7
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    invoke-static {v12, v4}, Lcom/google/crypto/tink/shaded/protobuf/d1;->a(Ljava/lang/Object;Landroidx/collection/h;)Z

    .line 154
    .line 155
    .line 156
    move-result v0
    :try_end_4
    .catch Lcom/google/crypto/tink/shaded/protobuf/c0; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_6

    .line 157
    if-nez v0, :cond_a

    .line 158
    .line 159
    :goto_8
    if-ge v10, v9, :cond_9

    .line 160
    .line 161
    aget v0, v8, v10

    .line 162
    .line 163
    invoke-virtual {v1, v0, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->l(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    add-int/lit8 v10, v10, 0x1

    .line 167
    .line 168
    goto :goto_8

    .line 169
    :cond_9
    :goto_9
    move-object v0, v2

    .line 170
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 171
    .line 172
    iput-object v12, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 173
    .line 174
    goto/16 :goto_12

    .line 175
    .line 176
    :cond_a
    move/from16 v18, v9

    .line 177
    .line 178
    move v15, v10

    .line 179
    move-object v9, v6

    .line 180
    move-object v10, v8

    .line 181
    move-object v6, v1

    .line 182
    move-object v8, v4

    .line 183
    goto/16 :goto_f

    .line 184
    .line 185
    :pswitch_0
    and-int v3, v3, v16

    .line 186
    .line 187
    move v15, v10

    .line 188
    int-to-long v10, v3

    .line 189
    :try_start_5
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 190
    .line 191
    .line 192
    move-result-object v3

    .line 193
    invoke-virtual {v4, v3, v6}, Landroidx/collection/h;->S(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v3

    .line 197
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 201
    .line 202
    .line 203
    :goto_a
    move-object v10, v8

    .line 204
    move/from16 v18, v9

    .line 205
    .line 206
    goto/16 :goto_e

    .line 207
    .line 208
    :catchall_0
    move-exception v0

    .line 209
    move-object v6, v1

    .line 210
    move-object v10, v8

    .line 211
    move v1, v9

    .line 212
    goto/16 :goto_14

    .line 213
    .line 214
    :catch_1
    move-object v10, v8

    .line 215
    move/from16 v18, v9

    .line 216
    .line 217
    :catch_2
    move-object v8, v4

    .line 218
    move-object v9, v6

    .line 219
    move-object v6, v1

    .line 220
    goto/16 :goto_10

    .line 221
    .line 222
    :pswitch_1
    move v15, v10

    .line 223
    and-int v3, v3, v16

    .line 224
    .line 225
    int-to-long v10, v3

    .line 226
    invoke-virtual {v4}, Landroidx/collection/h;->q0()J

    .line 227
    .line 228
    .line 229
    move-result-wide v18

    .line 230
    invoke-static/range {v18 .. v19}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 231
    .line 232
    .line 233
    move-result-object v3

    .line 234
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 238
    .line 239
    .line 240
    goto :goto_a

    .line 241
    :pswitch_2
    move v15, v10

    .line 242
    and-int v3, v3, v16

    .line 243
    .line 244
    int-to-long v10, v3

    .line 245
    invoke-virtual {v4}, Landroidx/collection/h;->m0()I

    .line 246
    .line 247
    .line 248
    move-result v3

    .line 249
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 250
    .line 251
    .line 252
    move-result-object v3

    .line 253
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 257
    .line 258
    .line 259
    goto :goto_a

    .line 260
    :pswitch_3
    move v15, v10

    .line 261
    and-int v3, v3, v16

    .line 262
    .line 263
    int-to-long v10, v3

    .line 264
    invoke-virtual {v4}, Landroidx/collection/h;->i0()J

    .line 265
    .line 266
    .line 267
    move-result-wide v18

    .line 268
    invoke-static/range {v18 .. v19}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 269
    .line 270
    .line 271
    move-result-object v3

    .line 272
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 276
    .line 277
    .line 278
    goto :goto_a

    .line 279
    :pswitch_4
    move v15, v10

    .line 280
    and-int v3, v3, v16

    .line 281
    .line 282
    int-to-long v10, v3

    .line 283
    invoke-virtual {v4}, Landroidx/collection/h;->e0()I

    .line 284
    .line 285
    .line 286
    move-result v3

    .line 287
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 288
    .line 289
    .line 290
    move-result-object v3

    .line 291
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 295
    .line 296
    .line 297
    goto :goto_a

    .line 298
    :pswitch_5
    move v15, v10

    .line 299
    invoke-virtual {v4}, Landroidx/collection/h;->A()I

    .line 300
    .line 301
    .line 302
    move-result v5

    .line 303
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->m(I)V

    .line 304
    .line 305
    .line 306
    and-int v3, v3, v16

    .line 307
    .line 308
    int-to-long v10, v3

    .line 309
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 310
    .line 311
    .line 312
    move-result-object v3

    .line 313
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 317
    .line 318
    .line 319
    goto :goto_a

    .line 320
    :pswitch_6
    move v15, v10

    .line 321
    and-int v3, v3, v16

    .line 322
    .line 323
    int-to-long v10, v3

    .line 324
    invoke-virtual {v4}, Landroidx/collection/h;->z0()I

    .line 325
    .line 326
    .line 327
    move-result v3

    .line 328
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 329
    .line 330
    .line 331
    move-result-object v3

    .line 332
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 336
    .line 337
    .line 338
    goto/16 :goto_a

    .line 339
    .line 340
    :pswitch_7
    move v15, v10

    .line 341
    and-int v3, v3, v16

    .line 342
    .line 343
    int-to-long v10, v3

    .line 344
    invoke-virtual {v4}, Landroidx/collection/h;->s()Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 345
    .line 346
    .line 347
    move-result-object v3

    .line 348
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 349
    .line 350
    .line 351
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 352
    .line 353
    .line 354
    goto/16 :goto_a

    .line 355
    .line 356
    :pswitch_8
    move v15, v10

    .line 357
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 358
    .line 359
    .line 360
    move-result v5

    .line 361
    if-eqz v5, :cond_b

    .line 362
    .line 363
    and-int v3, v3, v16

    .line 364
    .line 365
    int-to-long v10, v3

    .line 366
    sget-object v3, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 367
    .line 368
    invoke-virtual {v3, v2, v10, v11}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v3

    .line 372
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 373
    .line 374
    .line 375
    move-result-object v5

    .line 376
    invoke-virtual {v4, v5, v6}, Landroidx/collection/h;->d0(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v5

    .line 380
    invoke-static {v3, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 381
    .line 382
    .line 383
    move-result-object v3

    .line 384
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 385
    .line 386
    .line 387
    goto :goto_b

    .line 388
    :cond_b
    and-int v3, v3, v16

    .line 389
    .line 390
    int-to-long v10, v3

    .line 391
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 392
    .line 393
    .line 394
    move-result-object v3

    .line 395
    invoke-virtual {v4, v3, v6}, Landroidx/collection/h;->d0(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v3

    .line 399
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 400
    .line 401
    .line 402
    invoke-virtual {v1, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 403
    .line 404
    .line 405
    :goto_b
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 406
    .line 407
    .line 408
    goto/16 :goto_a

    .line 409
    .line 410
    :pswitch_9
    move v15, v10

    .line 411
    invoke-virtual {v1, v3, v4, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->I(ILandroidx/collection/h;Ljava/lang/Object;)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 415
    .line 416
    .line 417
    goto/16 :goto_a

    .line 418
    .line 419
    :pswitch_a
    move v15, v10

    .line 420
    and-int v3, v3, v16

    .line 421
    .line 422
    int-to-long v10, v3

    .line 423
    invoke-virtual {v4}, Landroidx/collection/h;->m()Z

    .line 424
    .line 425
    .line 426
    move-result v3

    .line 427
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 428
    .line 429
    .line 430
    move-result-object v3

    .line 431
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 432
    .line 433
    .line 434
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 435
    .line 436
    .line 437
    goto/16 :goto_a

    .line 438
    .line 439
    :pswitch_b
    move v15, v10

    .line 440
    and-int v3, v3, v16

    .line 441
    .line 442
    int-to-long v10, v3

    .line 443
    invoke-virtual {v4}, Landroidx/collection/h;->F()I

    .line 444
    .line 445
    .line 446
    move-result v3

    .line 447
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 448
    .line 449
    .line 450
    move-result-object v3

    .line 451
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 452
    .line 453
    .line 454
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 455
    .line 456
    .line 457
    goto/16 :goto_a

    .line 458
    .line 459
    :pswitch_c
    move v15, v10

    .line 460
    and-int v3, v3, v16

    .line 461
    .line 462
    int-to-long v10, v3

    .line 463
    invoke-virtual {v4}, Landroidx/collection/h;->J()J

    .line 464
    .line 465
    .line 466
    move-result-wide v18

    .line 467
    invoke-static/range {v18 .. v19}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 468
    .line 469
    .line 470
    move-result-object v3

    .line 471
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 472
    .line 473
    .line 474
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 475
    .line 476
    .line 477
    goto/16 :goto_a

    .line 478
    .line 479
    :pswitch_d
    move v15, v10

    .line 480
    and-int v3, v3, v16

    .line 481
    .line 482
    int-to-long v10, v3

    .line 483
    invoke-virtual {v4}, Landroidx/collection/h;->U()I

    .line 484
    .line 485
    .line 486
    move-result v3

    .line 487
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 488
    .line 489
    .line 490
    move-result-object v3

    .line 491
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 492
    .line 493
    .line 494
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 495
    .line 496
    .line 497
    goto/16 :goto_a

    .line 498
    .line 499
    :pswitch_e
    move v15, v10

    .line 500
    and-int v3, v3, v16

    .line 501
    .line 502
    int-to-long v10, v3

    .line 503
    invoke-virtual {v4}, Landroidx/collection/h;->D0()J

    .line 504
    .line 505
    .line 506
    move-result-wide v18

    .line 507
    invoke-static/range {v18 .. v19}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 508
    .line 509
    .line 510
    move-result-object v3

    .line 511
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 512
    .line 513
    .line 514
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 515
    .line 516
    .line 517
    goto/16 :goto_a

    .line 518
    .line 519
    :pswitch_f
    move v15, v10

    .line 520
    and-int v3, v3, v16

    .line 521
    .line 522
    int-to-long v10, v3

    .line 523
    invoke-virtual {v4}, Landroidx/collection/h;->Y()J

    .line 524
    .line 525
    .line 526
    move-result-wide v18

    .line 527
    invoke-static/range {v18 .. v19}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 528
    .line 529
    .line 530
    move-result-object v3

    .line 531
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 532
    .line 533
    .line 534
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 535
    .line 536
    .line 537
    goto/16 :goto_a

    .line 538
    .line 539
    :pswitch_10
    move v15, v10

    .line 540
    and-int v3, v3, v16

    .line 541
    .line 542
    int-to-long v10, v3

    .line 543
    invoke-virtual {v4}, Landroidx/collection/h;->N()F

    .line 544
    .line 545
    .line 546
    move-result v3

    .line 547
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 548
    .line 549
    .line 550
    move-result-object v3

    .line 551
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 552
    .line 553
    .line 554
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 555
    .line 556
    .line 557
    goto/16 :goto_a

    .line 558
    .line 559
    :pswitch_11
    move v15, v10

    .line 560
    and-int v3, v3, v16

    .line 561
    .line 562
    int-to-long v10, v3

    .line 563
    invoke-virtual {v4}, Landroidx/collection/h;->w()D

    .line 564
    .line 565
    .line 566
    move-result-wide v18

    .line 567
    invoke-static/range {v18 .. v19}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 568
    .line 569
    .line 570
    move-result-object v3

    .line 571
    invoke-static {v2, v10, v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 572
    .line 573
    .line 574
    invoke-virtual {v1, v0, v2, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 575
    .line 576
    .line 577
    goto/16 :goto_a

    .line 578
    .line 579
    :pswitch_12
    move v15, v10

    .line 580
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->n(I)Ljava/lang/Object;

    .line 581
    .line 582
    .line 583
    move-result-object v0

    .line 584
    invoke-virtual {v1, v13, v2, v0}, Lcom/google/crypto/tink/shaded/protobuf/r0;->u(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 585
    .line 586
    .line 587
    throw v17
    :try_end_5
    .catch Lcom/google/crypto/tink/shaded/protobuf/c0; {:try_start_5 .. :try_end_5} :catch_1
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 588
    :pswitch_13
    move v15, v10

    .line 589
    and-int v0, v3, v16

    .line 590
    .line 591
    move-object v10, v8

    .line 592
    move/from16 v18, v9

    .line 593
    .line 594
    int-to-long v8, v0

    .line 595
    :try_start_6
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 596
    .line 597
    .line 598
    move-result-object v0

    .line 599
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 600
    .line 601
    .line 602
    move-result-object v3

    .line 603
    invoke-virtual {v4, v3, v0, v6}, Landroidx/collection/h;->T(Ljava/util/List;Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)V

    .line 604
    .line 605
    .line 606
    goto/16 :goto_e

    .line 607
    .line 608
    :goto_c
    move-object v6, v1

    .line 609
    :goto_d
    move/from16 v1, v18

    .line 610
    .line 611
    goto/16 :goto_14

    .line 612
    .line 613
    :catchall_1
    move-exception v0

    .line 614
    goto :goto_c

    .line 615
    :pswitch_14
    move/from16 v18, v9

    .line 616
    .line 617
    move v15, v10

    .line 618
    move-object v10, v8

    .line 619
    and-int v0, v3, v16

    .line 620
    .line 621
    int-to-long v8, v0

    .line 622
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 623
    .line 624
    .line 625
    move-result-object v0

    .line 626
    invoke-virtual {v4, v0}, Landroidx/collection/h;->t0(Ljava/util/List;)V

    .line 627
    .line 628
    .line 629
    goto :goto_e

    .line 630
    :pswitch_15
    move/from16 v18, v9

    .line 631
    .line 632
    move v15, v10

    .line 633
    move-object v10, v8

    .line 634
    and-int v0, v3, v16

    .line 635
    .line 636
    int-to-long v8, v0

    .line 637
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 638
    .line 639
    .line 640
    move-result-object v0

    .line 641
    invoke-virtual {v4, v0}, Landroidx/collection/h;->p0(Ljava/util/List;)V

    .line 642
    .line 643
    .line 644
    goto :goto_e

    .line 645
    :pswitch_16
    move/from16 v18, v9

    .line 646
    .line 647
    move v15, v10

    .line 648
    move-object v10, v8

    .line 649
    and-int v0, v3, v16

    .line 650
    .line 651
    int-to-long v8, v0

    .line 652
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 653
    .line 654
    .line 655
    move-result-object v0

    .line 656
    invoke-virtual {v4, v0}, Landroidx/collection/h;->l0(Ljava/util/List;)V

    .line 657
    .line 658
    .line 659
    goto :goto_e

    .line 660
    :pswitch_17
    move/from16 v18, v9

    .line 661
    .line 662
    move v15, v10

    .line 663
    move-object v10, v8

    .line 664
    and-int v0, v3, v16

    .line 665
    .line 666
    int-to-long v8, v0

    .line 667
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 668
    .line 669
    .line 670
    move-result-object v0

    .line 671
    invoke-virtual {v4, v0}, Landroidx/collection/h;->h0(Ljava/util/List;)V

    .line 672
    .line 673
    .line 674
    goto :goto_e

    .line 675
    :pswitch_18
    move/from16 v18, v9

    .line 676
    .line 677
    move v15, v10

    .line 678
    move-object v10, v8

    .line 679
    and-int v0, v3, v16

    .line 680
    .line 681
    int-to-long v8, v0

    .line 682
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 683
    .line 684
    .line 685
    move-result-object v0

    .line 686
    invoke-virtual {v4, v0}, Landroidx/collection/h;->D(Ljava/util/List;)V

    .line 687
    .line 688
    .line 689
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->m(I)V

    .line 690
    .line 691
    .line 692
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 693
    .line 694
    :goto_e
    move-object v8, v4

    .line 695
    move-object v9, v6

    .line 696
    move-object v6, v1

    .line 697
    goto/16 :goto_f

    .line 698
    .line 699
    :pswitch_19
    move/from16 v18, v9

    .line 700
    .line 701
    move v15, v10

    .line 702
    move-object v10, v8

    .line 703
    and-int v0, v3, v16

    .line 704
    .line 705
    int-to-long v8, v0

    .line 706
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 707
    .line 708
    .line 709
    move-result-object v0

    .line 710
    invoke-virtual {v4, v0}, Landroidx/collection/h;->C0(Ljava/util/List;)V

    .line 711
    .line 712
    .line 713
    goto :goto_e

    .line 714
    :pswitch_1a
    move/from16 v18, v9

    .line 715
    .line 716
    move v15, v10

    .line 717
    move-object v10, v8

    .line 718
    and-int v0, v3, v16

    .line 719
    .line 720
    int-to-long v8, v0

    .line 721
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 722
    .line 723
    .line 724
    move-result-object v0

    .line 725
    invoke-virtual {v4, v0}, Landroidx/collection/h;->p(Ljava/util/List;)V

    .line 726
    .line 727
    .line 728
    goto :goto_e

    .line 729
    :pswitch_1b
    move/from16 v18, v9

    .line 730
    .line 731
    move v15, v10

    .line 732
    move-object v10, v8

    .line 733
    and-int v0, v3, v16

    .line 734
    .line 735
    int-to-long v8, v0

    .line 736
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 737
    .line 738
    .line 739
    move-result-object v0

    .line 740
    invoke-virtual {v4, v0}, Landroidx/collection/h;->I(Ljava/util/List;)V

    .line 741
    .line 742
    .line 743
    goto :goto_e

    .line 744
    :pswitch_1c
    move/from16 v18, v9

    .line 745
    .line 746
    move v15, v10

    .line 747
    move-object v10, v8

    .line 748
    and-int v0, v3, v16

    .line 749
    .line 750
    int-to-long v8, v0

    .line 751
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 752
    .line 753
    .line 754
    move-result-object v0

    .line 755
    invoke-virtual {v4, v0}, Landroidx/collection/h;->M(Ljava/util/List;)V

    .line 756
    .line 757
    .line 758
    goto :goto_e

    .line 759
    :pswitch_1d
    move/from16 v18, v9

    .line 760
    .line 761
    move v15, v10

    .line 762
    move-object v10, v8

    .line 763
    and-int v0, v3, v16

    .line 764
    .line 765
    int-to-long v8, v0

    .line 766
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 767
    .line 768
    .line 769
    move-result-object v0

    .line 770
    invoke-virtual {v4, v0}, Landroidx/collection/h;->X(Ljava/util/List;)V

    .line 771
    .line 772
    .line 773
    goto :goto_e

    .line 774
    :pswitch_1e
    move/from16 v18, v9

    .line 775
    .line 776
    move v15, v10

    .line 777
    move-object v10, v8

    .line 778
    and-int v0, v3, v16

    .line 779
    .line 780
    int-to-long v8, v0

    .line 781
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 782
    .line 783
    .line 784
    move-result-object v0

    .line 785
    invoke-virtual {v4, v0}, Landroidx/collection/h;->G0(Ljava/util/List;)V

    .line 786
    .line 787
    .line 788
    goto :goto_e

    .line 789
    :pswitch_1f
    move/from16 v18, v9

    .line 790
    .line 791
    move v15, v10

    .line 792
    move-object v10, v8

    .line 793
    and-int v0, v3, v16

    .line 794
    .line 795
    int-to-long v8, v0

    .line 796
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 797
    .line 798
    .line 799
    move-result-object v0

    .line 800
    invoke-virtual {v4, v0}, Landroidx/collection/h;->b0(Ljava/util/List;)V

    .line 801
    .line 802
    .line 803
    goto :goto_e

    .line 804
    :pswitch_20
    move/from16 v18, v9

    .line 805
    .line 806
    move v15, v10

    .line 807
    move-object v10, v8

    .line 808
    and-int v0, v3, v16

    .line 809
    .line 810
    int-to-long v8, v0

    .line 811
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 812
    .line 813
    .line 814
    move-result-object v0

    .line 815
    invoke-virtual {v4, v0}, Landroidx/collection/h;->Q(Ljava/util/List;)V

    .line 816
    .line 817
    .line 818
    goto :goto_e

    .line 819
    :pswitch_21
    move/from16 v18, v9

    .line 820
    .line 821
    move v15, v10

    .line 822
    move-object v10, v8

    .line 823
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 824
    .line 825
    .line 826
    move-result-wide v8

    .line 827
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 828
    .line 829
    .line 830
    move-result-object v0

    .line 831
    invoke-virtual {v4, v0}, Landroidx/collection/h;->z(Ljava/util/List;)V

    .line 832
    .line 833
    .line 834
    goto/16 :goto_e

    .line 835
    .line 836
    :pswitch_22
    move/from16 v18, v9

    .line 837
    .line 838
    move v15, v10

    .line 839
    move-object v10, v8

    .line 840
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 841
    .line 842
    .line 843
    move-result-wide v8

    .line 844
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 845
    .line 846
    .line 847
    move-result-object v0

    .line 848
    invoke-virtual {v4, v0}, Landroidx/collection/h;->t0(Ljava/util/List;)V

    .line 849
    .line 850
    .line 851
    goto/16 :goto_e

    .line 852
    .line 853
    :pswitch_23
    move/from16 v18, v9

    .line 854
    .line 855
    move v15, v10

    .line 856
    move-object v10, v8

    .line 857
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 858
    .line 859
    .line 860
    move-result-wide v8

    .line 861
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 862
    .line 863
    .line 864
    move-result-object v0

    .line 865
    invoke-virtual {v4, v0}, Landroidx/collection/h;->p0(Ljava/util/List;)V

    .line 866
    .line 867
    .line 868
    goto/16 :goto_e

    .line 869
    .line 870
    :pswitch_24
    move/from16 v18, v9

    .line 871
    .line 872
    move v15, v10

    .line 873
    move-object v10, v8

    .line 874
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 875
    .line 876
    .line 877
    move-result-wide v8

    .line 878
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 879
    .line 880
    .line 881
    move-result-object v0

    .line 882
    invoke-virtual {v4, v0}, Landroidx/collection/h;->l0(Ljava/util/List;)V

    .line 883
    .line 884
    .line 885
    goto/16 :goto_e

    .line 886
    .line 887
    :pswitch_25
    move/from16 v18, v9

    .line 888
    .line 889
    move v15, v10

    .line 890
    move-object v10, v8

    .line 891
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 892
    .line 893
    .line 894
    move-result-wide v8

    .line 895
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 896
    .line 897
    .line 898
    move-result-object v0

    .line 899
    invoke-virtual {v4, v0}, Landroidx/collection/h;->h0(Ljava/util/List;)V

    .line 900
    .line 901
    .line 902
    goto/16 :goto_e

    .line 903
    .line 904
    :pswitch_26
    move/from16 v18, v9

    .line 905
    .line 906
    move v15, v10

    .line 907
    move-object v10, v8

    .line 908
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 909
    .line 910
    .line 911
    move-result-wide v8

    .line 912
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 913
    .line 914
    .line 915
    move-result-object v3

    .line 916
    invoke-virtual {v4, v3}, Landroidx/collection/h;->D(Ljava/util/List;)V

    .line 917
    .line 918
    .line 919
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->m(I)V

    .line 920
    .line 921
    .line 922
    invoke-static {v0, v3, v12, v7}, Lcom/google/crypto/tink/shaded/protobuf/b1;->v(ILjava/util/List;Ljava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/d1;)Ljava/lang/Object;

    .line 923
    .line 924
    .line 925
    goto/16 :goto_e

    .line 926
    .line 927
    :pswitch_27
    move/from16 v18, v9

    .line 928
    .line 929
    move v15, v10

    .line 930
    move-object v10, v8

    .line 931
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 932
    .line 933
    .line 934
    move-result-wide v8

    .line 935
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 936
    .line 937
    .line 938
    move-result-object v0

    .line 939
    invoke-virtual {v4, v0}, Landroidx/collection/h;->C0(Ljava/util/List;)V

    .line 940
    .line 941
    .line 942
    goto/16 :goto_e

    .line 943
    .line 944
    :pswitch_28
    move/from16 v18, v9

    .line 945
    .line 946
    move v15, v10

    .line 947
    move-object v10, v8

    .line 948
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 949
    .line 950
    .line 951
    move-result-wide v8

    .line 952
    invoke-virtual {v11, v8, v9, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 953
    .line 954
    .line 955
    move-result-object v0

    .line 956
    invoke-virtual {v4, v0}, Landroidx/collection/h;->v(Ljava/util/List;)V

    .line 957
    .line 958
    .line 959
    goto/16 :goto_e

    .line 960
    .line 961
    :pswitch_29
    move/from16 v18, v9

    .line 962
    .line 963
    move v15, v10

    .line 964
    move-object v10, v8

    .line 965
    invoke-virtual {v1, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 966
    .line 967
    .line 968
    move-result-object v5

    .line 969
    invoke-virtual/range {v1 .. v6}, Lcom/google/crypto/tink/shaded/protobuf/r0;->H(Ljava/lang/Object;ILandroidx/collection/h;Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)V
    :try_end_6
    .catch Lcom/google/crypto/tink/shaded/protobuf/c0; {:try_start_6 .. :try_end_6} :catch_2
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 970
    .line 971
    .line 972
    move-object v8, v4

    .line 973
    move-object v9, v6

    .line 974
    move-object v6, v1

    .line 975
    goto/16 :goto_f

    .line 976
    .line 977
    :pswitch_2a
    move/from16 v18, v9

    .line 978
    .line 979
    move v15, v10

    .line 980
    move-object v9, v6

    .line 981
    move-object v10, v8

    .line 982
    move-object v6, v1

    .line 983
    move-object v8, v4

    .line 984
    const/high16 v0, 0x20000000

    .line 985
    .line 986
    and-int/2addr v0, v3

    .line 987
    if-eqz v0, :cond_c

    .line 988
    .line 989
    and-int v0, v3, v16

    .line 990
    .line 991
    int-to-long v0, v0

    .line 992
    :try_start_7
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 993
    .line 994
    .line 995
    move-result-object v0

    .line 996
    const/4 v1, 0x1

    .line 997
    invoke-virtual {v8, v0, v1}, Landroidx/collection/h;->x0(Ljava/util/List;Z)V

    .line 998
    .line 999
    .line 1000
    goto/16 :goto_f

    .line 1001
    .line 1002
    :cond_c
    and-int v0, v3, v16

    .line 1003
    .line 1004
    int-to-long v0, v0

    .line 1005
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v0

    .line 1009
    invoke-virtual {v8, v0, v5}, Landroidx/collection/h;->x0(Ljava/util/List;Z)V

    .line 1010
    .line 1011
    .line 1012
    goto/16 :goto_f

    .line 1013
    .line 1014
    :pswitch_2b
    move/from16 v18, v9

    .line 1015
    .line 1016
    move v15, v10

    .line 1017
    move-object v9, v6

    .line 1018
    move-object v10, v8

    .line 1019
    move-object v6, v1

    .line 1020
    move-object v8, v4

    .line 1021
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1022
    .line 1023
    .line 1024
    move-result-wide v0

    .line 1025
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 1026
    .line 1027
    .line 1028
    move-result-object v0

    .line 1029
    invoke-virtual {v8, v0}, Landroidx/collection/h;->p(Ljava/util/List;)V

    .line 1030
    .line 1031
    .line 1032
    goto/16 :goto_f

    .line 1033
    .line 1034
    :catchall_2
    move-exception v0

    .line 1035
    goto/16 :goto_d

    .line 1036
    .line 1037
    :pswitch_2c
    move/from16 v18, v9

    .line 1038
    .line 1039
    move v15, v10

    .line 1040
    move-object v9, v6

    .line 1041
    move-object v10, v8

    .line 1042
    move-object v6, v1

    .line 1043
    move-object v8, v4

    .line 1044
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1045
    .line 1046
    .line 1047
    move-result-wide v0

    .line 1048
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v0

    .line 1052
    invoke-virtual {v8, v0}, Landroidx/collection/h;->I(Ljava/util/List;)V

    .line 1053
    .line 1054
    .line 1055
    goto/16 :goto_f

    .line 1056
    .line 1057
    :pswitch_2d
    move/from16 v18, v9

    .line 1058
    .line 1059
    move v15, v10

    .line 1060
    move-object v9, v6

    .line 1061
    move-object v10, v8

    .line 1062
    move-object v6, v1

    .line 1063
    move-object v8, v4

    .line 1064
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1065
    .line 1066
    .line 1067
    move-result-wide v0

    .line 1068
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v0

    .line 1072
    invoke-virtual {v8, v0}, Landroidx/collection/h;->M(Ljava/util/List;)V

    .line 1073
    .line 1074
    .line 1075
    goto/16 :goto_f

    .line 1076
    .line 1077
    :pswitch_2e
    move/from16 v18, v9

    .line 1078
    .line 1079
    move v15, v10

    .line 1080
    move-object v9, v6

    .line 1081
    move-object v10, v8

    .line 1082
    move-object v6, v1

    .line 1083
    move-object v8, v4

    .line 1084
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1085
    .line 1086
    .line 1087
    move-result-wide v0

    .line 1088
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 1089
    .line 1090
    .line 1091
    move-result-object v0

    .line 1092
    invoke-virtual {v8, v0}, Landroidx/collection/h;->X(Ljava/util/List;)V

    .line 1093
    .line 1094
    .line 1095
    goto/16 :goto_f

    .line 1096
    .line 1097
    :pswitch_2f
    move/from16 v18, v9

    .line 1098
    .line 1099
    move v15, v10

    .line 1100
    move-object v9, v6

    .line 1101
    move-object v10, v8

    .line 1102
    move-object v6, v1

    .line 1103
    move-object v8, v4

    .line 1104
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1105
    .line 1106
    .line 1107
    move-result-wide v0

    .line 1108
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 1109
    .line 1110
    .line 1111
    move-result-object v0

    .line 1112
    invoke-virtual {v8, v0}, Landroidx/collection/h;->G0(Ljava/util/List;)V

    .line 1113
    .line 1114
    .line 1115
    goto/16 :goto_f

    .line 1116
    .line 1117
    :pswitch_30
    move/from16 v18, v9

    .line 1118
    .line 1119
    move v15, v10

    .line 1120
    move-object v9, v6

    .line 1121
    move-object v10, v8

    .line 1122
    move-object v6, v1

    .line 1123
    move-object v8, v4

    .line 1124
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1125
    .line 1126
    .line 1127
    move-result-wide v0

    .line 1128
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 1129
    .line 1130
    .line 1131
    move-result-object v0

    .line 1132
    invoke-virtual {v8, v0}, Landroidx/collection/h;->b0(Ljava/util/List;)V

    .line 1133
    .line 1134
    .line 1135
    goto/16 :goto_f

    .line 1136
    .line 1137
    :pswitch_31
    move/from16 v18, v9

    .line 1138
    .line 1139
    move v15, v10

    .line 1140
    move-object v9, v6

    .line 1141
    move-object v10, v8

    .line 1142
    move-object v6, v1

    .line 1143
    move-object v8, v4

    .line 1144
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1145
    .line 1146
    .line 1147
    move-result-wide v0

    .line 1148
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 1149
    .line 1150
    .line 1151
    move-result-object v0

    .line 1152
    invoke-virtual {v8, v0}, Landroidx/collection/h;->Q(Ljava/util/List;)V

    .line 1153
    .line 1154
    .line 1155
    goto/16 :goto_f

    .line 1156
    .line 1157
    :pswitch_32
    move/from16 v18, v9

    .line 1158
    .line 1159
    move v15, v10

    .line 1160
    move-object v9, v6

    .line 1161
    move-object v10, v8

    .line 1162
    move-object v6, v1

    .line 1163
    move-object v8, v4

    .line 1164
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1165
    .line 1166
    .line 1167
    move-result-wide v0

    .line 1168
    invoke-virtual {v11, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->c(JLjava/lang/Object;)Ljava/util/List;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v0

    .line 1172
    invoke-virtual {v8, v0}, Landroidx/collection/h;->z(Ljava/util/List;)V

    .line 1173
    .line 1174
    .line 1175
    goto/16 :goto_f

    .line 1176
    .line 1177
    :pswitch_33
    move/from16 v18, v9

    .line 1178
    .line 1179
    move v15, v10

    .line 1180
    move-object v9, v6

    .line 1181
    move-object v10, v8

    .line 1182
    move-object v6, v1

    .line 1183
    move-object v8, v4

    .line 1184
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1185
    .line 1186
    .line 1187
    move-result v0

    .line 1188
    if-eqz v0, :cond_d

    .line 1189
    .line 1190
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1191
    .line 1192
    .line 1193
    move-result-wide v0

    .line 1194
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1195
    .line 1196
    invoke-virtual {v4, v2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1197
    .line 1198
    .line 1199
    move-result-object v0

    .line 1200
    invoke-virtual {v6, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1201
    .line 1202
    .line 1203
    move-result-object v1

    .line 1204
    invoke-virtual {v8, v1, v9}, Landroidx/collection/h;->S(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 1205
    .line 1206
    .line 1207
    move-result-object v1

    .line 1208
    invoke-static {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1209
    .line 1210
    .line 1211
    move-result-object v0

    .line 1212
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1213
    .line 1214
    .line 1215
    move-result-wide v3

    .line 1216
    invoke-static {v2, v3, v4, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 1217
    .line 1218
    .line 1219
    goto/16 :goto_f

    .line 1220
    .line 1221
    :cond_d
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1222
    .line 1223
    .line 1224
    move-result-wide v0

    .line 1225
    invoke-virtual {v6, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v3

    .line 1229
    invoke-virtual {v8, v3, v9}, Landroidx/collection/h;->S(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 1230
    .line 1231
    .line 1232
    move-result-object v3

    .line 1233
    invoke-static {v2, v0, v1, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 1234
    .line 1235
    .line 1236
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1237
    .line 1238
    .line 1239
    goto/16 :goto_f

    .line 1240
    .line 1241
    :pswitch_34
    move/from16 v18, v9

    .line 1242
    .line 1243
    move v15, v10

    .line 1244
    move-object v9, v6

    .line 1245
    move-object v10, v8

    .line 1246
    move-object v6, v1

    .line 1247
    move-object v8, v4

    .line 1248
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1249
    .line 1250
    .line 1251
    move-result-wide v0

    .line 1252
    invoke-virtual {v8}, Landroidx/collection/h;->q0()J

    .line 1253
    .line 1254
    .line 1255
    move-result-wide v3

    .line 1256
    invoke-static {v0, v1, v2, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 1257
    .line 1258
    .line 1259
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1260
    .line 1261
    .line 1262
    goto/16 :goto_f

    .line 1263
    .line 1264
    :pswitch_35
    move/from16 v18, v9

    .line 1265
    .line 1266
    move v15, v10

    .line 1267
    move-object v9, v6

    .line 1268
    move-object v10, v8

    .line 1269
    move-object v6, v1

    .line 1270
    move-object v8, v4

    .line 1271
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1272
    .line 1273
    .line 1274
    move-result-wide v0

    .line 1275
    invoke-virtual {v8}, Landroidx/collection/h;->m0()I

    .line 1276
    .line 1277
    .line 1278
    move-result v3

    .line 1279
    invoke-static {v0, v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 1280
    .line 1281
    .line 1282
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1283
    .line 1284
    .line 1285
    goto/16 :goto_f

    .line 1286
    .line 1287
    :pswitch_36
    move/from16 v18, v9

    .line 1288
    .line 1289
    move v15, v10

    .line 1290
    move-object v9, v6

    .line 1291
    move-object v10, v8

    .line 1292
    move-object v6, v1

    .line 1293
    move-object v8, v4

    .line 1294
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1295
    .line 1296
    .line 1297
    move-result-wide v0

    .line 1298
    invoke-virtual {v8}, Landroidx/collection/h;->i0()J

    .line 1299
    .line 1300
    .line 1301
    move-result-wide v3

    .line 1302
    invoke-static {v0, v1, v2, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 1303
    .line 1304
    .line 1305
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1306
    .line 1307
    .line 1308
    goto/16 :goto_f

    .line 1309
    .line 1310
    :pswitch_37
    move/from16 v18, v9

    .line 1311
    .line 1312
    move v15, v10

    .line 1313
    move-object v9, v6

    .line 1314
    move-object v10, v8

    .line 1315
    move-object v6, v1

    .line 1316
    move-object v8, v4

    .line 1317
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1318
    .line 1319
    .line 1320
    move-result-wide v0

    .line 1321
    invoke-virtual {v8}, Landroidx/collection/h;->e0()I

    .line 1322
    .line 1323
    .line 1324
    move-result v3

    .line 1325
    invoke-static {v0, v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 1326
    .line 1327
    .line 1328
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1329
    .line 1330
    .line 1331
    goto/16 :goto_f

    .line 1332
    .line 1333
    :pswitch_38
    move/from16 v18, v9

    .line 1334
    .line 1335
    move v15, v10

    .line 1336
    move-object v9, v6

    .line 1337
    move-object v10, v8

    .line 1338
    move-object v6, v1

    .line 1339
    move-object v8, v4

    .line 1340
    invoke-virtual {v8}, Landroidx/collection/h;->A()I

    .line 1341
    .line 1342
    .line 1343
    move-result v0

    .line 1344
    invoke-virtual {v6, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->m(I)V

    .line 1345
    .line 1346
    .line 1347
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1348
    .line 1349
    .line 1350
    move-result-wide v3

    .line 1351
    invoke-static {v3, v4, v2, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 1352
    .line 1353
    .line 1354
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1355
    .line 1356
    .line 1357
    goto/16 :goto_f

    .line 1358
    .line 1359
    :pswitch_39
    move/from16 v18, v9

    .line 1360
    .line 1361
    move v15, v10

    .line 1362
    move-object v9, v6

    .line 1363
    move-object v10, v8

    .line 1364
    move-object v6, v1

    .line 1365
    move-object v8, v4

    .line 1366
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1367
    .line 1368
    .line 1369
    move-result-wide v0

    .line 1370
    invoke-virtual {v8}, Landroidx/collection/h;->z0()I

    .line 1371
    .line 1372
    .line 1373
    move-result v3

    .line 1374
    invoke-static {v0, v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 1375
    .line 1376
    .line 1377
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1378
    .line 1379
    .line 1380
    goto/16 :goto_f

    .line 1381
    .line 1382
    :pswitch_3a
    move/from16 v18, v9

    .line 1383
    .line 1384
    move v15, v10

    .line 1385
    move-object v9, v6

    .line 1386
    move-object v10, v8

    .line 1387
    move-object v6, v1

    .line 1388
    move-object v8, v4

    .line 1389
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1390
    .line 1391
    .line 1392
    move-result-wide v0

    .line 1393
    invoke-virtual {v8}, Landroidx/collection/h;->s()Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 1394
    .line 1395
    .line 1396
    move-result-object v3

    .line 1397
    invoke-static {v2, v0, v1, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 1398
    .line 1399
    .line 1400
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1401
    .line 1402
    .line 1403
    goto/16 :goto_f

    .line 1404
    .line 1405
    :pswitch_3b
    move/from16 v18, v9

    .line 1406
    .line 1407
    move v15, v10

    .line 1408
    move-object v9, v6

    .line 1409
    move-object v10, v8

    .line 1410
    move-object v6, v1

    .line 1411
    move-object v8, v4

    .line 1412
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1413
    .line 1414
    .line 1415
    move-result v0

    .line 1416
    if-eqz v0, :cond_e

    .line 1417
    .line 1418
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1419
    .line 1420
    .line 1421
    move-result-wide v0

    .line 1422
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1423
    .line 1424
    invoke-virtual {v4, v2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1425
    .line 1426
    .line 1427
    move-result-object v0

    .line 1428
    invoke-virtual {v6, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1429
    .line 1430
    .line 1431
    move-result-object v1

    .line 1432
    invoke-virtual {v8, v1, v9}, Landroidx/collection/h;->d0(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 1433
    .line 1434
    .line 1435
    move-result-object v1

    .line 1436
    invoke-static {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1437
    .line 1438
    .line 1439
    move-result-object v0

    .line 1440
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1441
    .line 1442
    .line 1443
    move-result-wide v3

    .line 1444
    invoke-static {v2, v3, v4, v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 1445
    .line 1446
    .line 1447
    goto/16 :goto_f

    .line 1448
    .line 1449
    :cond_e
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1450
    .line 1451
    .line 1452
    move-result-wide v0

    .line 1453
    invoke-virtual {v6, v13}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1454
    .line 1455
    .line 1456
    move-result-object v3

    .line 1457
    invoke-virtual {v8, v3, v9}, Landroidx/collection/h;->d0(Lcom/google/crypto/tink/shaded/protobuf/a1;Lcom/google/crypto/tink/shaded/protobuf/p;)Ljava/lang/Object;

    .line 1458
    .line 1459
    .line 1460
    move-result-object v3

    .line 1461
    invoke-static {v2, v0, v1, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 1462
    .line 1463
    .line 1464
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1465
    .line 1466
    .line 1467
    goto/16 :goto_f

    .line 1468
    .line 1469
    :pswitch_3c
    move/from16 v18, v9

    .line 1470
    .line 1471
    move v15, v10

    .line 1472
    move-object v9, v6

    .line 1473
    move-object v10, v8

    .line 1474
    move-object v6, v1

    .line 1475
    move-object v8, v4

    .line 1476
    invoke-virtual {v6, v3, v8, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->I(ILandroidx/collection/h;Ljava/lang/Object;)V

    .line 1477
    .line 1478
    .line 1479
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1480
    .line 1481
    .line 1482
    goto/16 :goto_f

    .line 1483
    .line 1484
    :pswitch_3d
    move/from16 v18, v9

    .line 1485
    .line 1486
    move v15, v10

    .line 1487
    move-object v9, v6

    .line 1488
    move-object v10, v8

    .line 1489
    move-object v6, v1

    .line 1490
    move-object v8, v4

    .line 1491
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1492
    .line 1493
    .line 1494
    move-result-wide v0

    .line 1495
    invoke-virtual {v8}, Landroidx/collection/h;->m()Z

    .line 1496
    .line 1497
    .line 1498
    move-result v3

    .line 1499
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1500
    .line 1501
    invoke-virtual {v4, v2, v0, v1, v3}, Lcom/google/crypto/tink/shaded/protobuf/k1;->k(Ljava/lang/Object;JZ)V

    .line 1502
    .line 1503
    .line 1504
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1505
    .line 1506
    .line 1507
    goto/16 :goto_f

    .line 1508
    .line 1509
    :pswitch_3e
    move/from16 v18, v9

    .line 1510
    .line 1511
    move v15, v10

    .line 1512
    move-object v9, v6

    .line 1513
    move-object v10, v8

    .line 1514
    move-object v6, v1

    .line 1515
    move-object v8, v4

    .line 1516
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1517
    .line 1518
    .line 1519
    move-result-wide v0

    .line 1520
    invoke-virtual {v8}, Landroidx/collection/h;->F()I

    .line 1521
    .line 1522
    .line 1523
    move-result v3

    .line 1524
    invoke-static {v0, v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 1525
    .line 1526
    .line 1527
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1528
    .line 1529
    .line 1530
    goto/16 :goto_f

    .line 1531
    .line 1532
    :pswitch_3f
    move/from16 v18, v9

    .line 1533
    .line 1534
    move v15, v10

    .line 1535
    move-object v9, v6

    .line 1536
    move-object v10, v8

    .line 1537
    move-object v6, v1

    .line 1538
    move-object v8, v4

    .line 1539
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1540
    .line 1541
    .line 1542
    move-result-wide v0

    .line 1543
    invoke-virtual {v8}, Landroidx/collection/h;->J()J

    .line 1544
    .line 1545
    .line 1546
    move-result-wide v3

    .line 1547
    invoke-static {v0, v1, v2, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 1548
    .line 1549
    .line 1550
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1551
    .line 1552
    .line 1553
    goto/16 :goto_f

    .line 1554
    .line 1555
    :pswitch_40
    move/from16 v18, v9

    .line 1556
    .line 1557
    move v15, v10

    .line 1558
    move-object v9, v6

    .line 1559
    move-object v10, v8

    .line 1560
    move-object v6, v1

    .line 1561
    move-object v8, v4

    .line 1562
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1563
    .line 1564
    .line 1565
    move-result-wide v0

    .line 1566
    invoke-virtual {v8}, Landroidx/collection/h;->U()I

    .line 1567
    .line 1568
    .line 1569
    move-result v3

    .line 1570
    invoke-static {v0, v1, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 1571
    .line 1572
    .line 1573
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1574
    .line 1575
    .line 1576
    goto/16 :goto_f

    .line 1577
    .line 1578
    :pswitch_41
    move/from16 v18, v9

    .line 1579
    .line 1580
    move v15, v10

    .line 1581
    move-object v9, v6

    .line 1582
    move-object v10, v8

    .line 1583
    move-object v6, v1

    .line 1584
    move-object v8, v4

    .line 1585
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1586
    .line 1587
    .line 1588
    move-result-wide v0

    .line 1589
    invoke-virtual {v8}, Landroidx/collection/h;->D0()J

    .line 1590
    .line 1591
    .line 1592
    move-result-wide v3

    .line 1593
    invoke-static {v0, v1, v2, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 1594
    .line 1595
    .line 1596
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1597
    .line 1598
    .line 1599
    goto :goto_f

    .line 1600
    :pswitch_42
    move/from16 v18, v9

    .line 1601
    .line 1602
    move v15, v10

    .line 1603
    move-object v9, v6

    .line 1604
    move-object v10, v8

    .line 1605
    move-object v6, v1

    .line 1606
    move-object v8, v4

    .line 1607
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1608
    .line 1609
    .line 1610
    move-result-wide v0

    .line 1611
    invoke-virtual {v8}, Landroidx/collection/h;->Y()J

    .line 1612
    .line 1613
    .line 1614
    move-result-wide v3

    .line 1615
    invoke-static {v0, v1, v2, v3, v4}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 1616
    .line 1617
    .line 1618
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1619
    .line 1620
    .line 1621
    goto :goto_f

    .line 1622
    :pswitch_43
    move/from16 v18, v9

    .line 1623
    .line 1624
    move v15, v10

    .line 1625
    move-object v9, v6

    .line 1626
    move-object v10, v8

    .line 1627
    move-object v6, v1

    .line 1628
    move-object v8, v4

    .line 1629
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1630
    .line 1631
    .line 1632
    move-result-wide v0

    .line 1633
    invoke-virtual {v8}, Landroidx/collection/h;->N()F

    .line 1634
    .line 1635
    .line 1636
    move-result v3

    .line 1637
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1638
    .line 1639
    invoke-virtual {v4, v2, v0, v1, v3}, Lcom/google/crypto/tink/shaded/protobuf/k1;->n(Ljava/lang/Object;JF)V

    .line 1640
    .line 1641
    .line 1642
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 1643
    .line 1644
    .line 1645
    goto :goto_f

    .line 1646
    :pswitch_44
    move/from16 v18, v9

    .line 1647
    .line 1648
    move v15, v10

    .line 1649
    move-object v9, v6

    .line 1650
    move-object v10, v8

    .line 1651
    move-object v6, v1

    .line 1652
    move-object v8, v4

    .line 1653
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->z(I)J

    .line 1654
    .line 1655
    .line 1656
    move-result-wide v0

    .line 1657
    invoke-virtual {v8}, Landroidx/collection/h;->w()D

    .line 1658
    .line 1659
    .line 1660
    move-result-wide v4
    :try_end_7
    .catch Lcom/google/crypto/tink/shaded/protobuf/c0; {:try_start_7 .. :try_end_7} :catch_6
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 1661
    move-wide v2, v0

    .line 1662
    :try_start_8
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;
    :try_end_8
    .catch Lcom/google/crypto/tink/shaded/protobuf/c0; {:try_start_8 .. :try_end_8} :catch_4
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    .line 1663
    .line 1664
    move-object/from16 v1, p1

    .line 1665
    .line 1666
    :try_start_9
    invoke-virtual/range {v0 .. v5}, Lcom/google/crypto/tink/shaded/protobuf/k1;->m(Ljava/lang/Object;JD)V
    :try_end_9
    .catch Lcom/google/crypto/tink/shaded/protobuf/c0; {:try_start_9 .. :try_end_9} :catch_3
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 1667
    .line 1668
    .line 1669
    move-object v2, v1

    .line 1670
    :try_start_a
    invoke-virtual {v6, v13, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V
    :try_end_a
    .catch Lcom/google/crypto/tink/shaded/protobuf/c0; {:try_start_a .. :try_end_a} :catch_6
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 1671
    .line 1672
    .line 1673
    :cond_f
    :goto_f
    move/from16 v1, v18

    .line 1674
    .line 1675
    goto :goto_13

    .line 1676
    :catchall_3
    move-exception v0

    .line 1677
    move-object v2, v1

    .line 1678
    goto/16 :goto_d

    .line 1679
    .line 1680
    :catch_3
    move-object v2, v1

    .line 1681
    goto :goto_10

    .line 1682
    :catchall_4
    move-exception v0

    .line 1683
    move-object/from16 v2, p1

    .line 1684
    .line 1685
    goto/16 :goto_d

    .line 1686
    .line 1687
    :catch_4
    move-object/from16 v2, p1

    .line 1688
    .line 1689
    goto :goto_10

    .line 1690
    :catchall_5
    move-exception v0

    .line 1691
    move-object v6, v1

    .line 1692
    move/from16 v18, v9

    .line 1693
    .line 1694
    move v15, v10

    .line 1695
    move-object v10, v8

    .line 1696
    goto/16 :goto_d

    .line 1697
    .line 1698
    :catch_5
    move/from16 v18, v9

    .line 1699
    .line 1700
    move v15, v10

    .line 1701
    const/16 v17, 0x0

    .line 1702
    .line 1703
    goto/16 :goto_6

    .line 1704
    .line 1705
    :catch_6
    :goto_10
    :try_start_b
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1706
    .line 1707
    .line 1708
    if-nez v12, :cond_11

    .line 1709
    .line 1710
    move-object v0, v2

    .line 1711
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1712
    .line 1713
    iget-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 1714
    .line 1715
    if-ne v1, v14, :cond_10

    .line 1716
    .line 1717
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c1;->b()Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 1718
    .line 1719
    .line 1720
    move-result-object v1

    .line 1721
    iput-object v1, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 1722
    .line 1723
    :cond_10
    move-object v12, v1

    .line 1724
    :cond_11
    invoke-static {v12, v8}, Lcom/google/crypto/tink/shaded/protobuf/d1;->a(Ljava/lang/Object;Landroidx/collection/h;)Z

    .line 1725
    .line 1726
    .line 1727
    move-result v0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_2

    .line 1728
    if-nez v0, :cond_f

    .line 1729
    .line 1730
    move/from16 v1, v18

    .line 1731
    .line 1732
    :goto_11
    if-ge v15, v1, :cond_12

    .line 1733
    .line 1734
    aget v0, v10, v15

    .line 1735
    .line 1736
    invoke-virtual {v6, v0, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->l(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1737
    .line 1738
    .line 1739
    add-int/lit8 v15, v15, 0x1

    .line 1740
    .line 1741
    goto :goto_11

    .line 1742
    :cond_12
    if-eqz v12, :cond_13

    .line 1743
    .line 1744
    goto/16 :goto_9

    .line 1745
    .line 1746
    :cond_13
    :goto_12
    return-void

    .line 1747
    :goto_13
    move-object v4, v9

    .line 1748
    move v9, v1

    .line 1749
    move-object v1, v6

    .line 1750
    move-object v6, v4

    .line 1751
    move-object v4, v8

    .line 1752
    move-object v8, v10

    .line 1753
    move v10, v15

    .line 1754
    goto/16 :goto_0

    .line 1755
    .line 1756
    :catchall_6
    move-exception v0

    .line 1757
    goto/16 :goto_2

    .line 1758
    .line 1759
    :goto_14
    if-ge v15, v1, :cond_14

    .line 1760
    .line 1761
    aget v3, v10, v15

    .line 1762
    .line 1763
    invoke-virtual {v6, v3, v2, v12}, Lcom/google/crypto/tink/shaded/protobuf/r0;->l(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1764
    .line 1765
    .line 1766
    add-int/lit8 v15, v15, 0x1

    .line 1767
    .line 1768
    goto :goto_14

    .line 1769
    :cond_14
    if-eqz v12, :cond_15

    .line 1770
    .line 1771
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1772
    .line 1773
    .line 1774
    move-object v1, v2

    .line 1775
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1776
    .line 1777
    iput-object v12, v1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 1778
    .line 1779
    :cond_15
    throw v0

    .line 1780
    nop

    .line 1781
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final g(Lcom/google/crypto/tink/shaded/protobuf/x;Lcom/google/crypto/tink/shaded/protobuf/x;)Z
    .locals 11

    .line 1
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    move v3, v2

    .line 6
    :goto_0
    const/4 v4, 0x1

    .line 7
    if-ge v3, v1, :cond_2

    .line 8
    .line 9
    invoke-virtual {p0, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 10
    .line 11
    .line 12
    move-result v5

    .line 13
    const v6, 0xfffff

    .line 14
    .line 15
    .line 16
    and-int v7, v5, v6

    .line 17
    .line 18
    int-to-long v7, v7

    .line 19
    invoke-static {v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    packed-switch v5, :pswitch_data_0

    .line 24
    .line 25
    .line 26
    goto/16 :goto_1

    .line 27
    .line 28
    :pswitch_0
    add-int/lit8 v5, v3, 0x2

    .line 29
    .line 30
    aget v5, v0, v5

    .line 31
    .line 32
    and-int/2addr v5, v6

    .line 33
    int-to-long v5, v5

    .line 34
    sget-object v9, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 35
    .line 36
    invoke-virtual {v9, v5, v6, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 37
    .line 38
    .line 39
    move-result v10

    .line 40
    invoke-virtual {v9, v5, v6, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-ne v10, v5, :cond_0

    .line 45
    .line 46
    invoke-virtual {v9, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    invoke-virtual {v9, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v6

    .line 54
    invoke-static {v5, v6}, Lcom/google/crypto/tink/shaded/protobuf/b1;->y(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    if-eqz v5, :cond_0

    .line 59
    .line 60
    goto/16 :goto_1

    .line 61
    .line 62
    :cond_0
    move v4, v2

    .line 63
    goto/16 :goto_1

    .line 64
    .line 65
    :pswitch_1
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 66
    .line 67
    invoke-virtual {v4, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    invoke-virtual {v4, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    invoke-static {v5, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->y(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    goto/16 :goto_1

    .line 80
    .line 81
    :pswitch_2
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 82
    .line 83
    invoke-virtual {v4, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    invoke-virtual {v4, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    invoke-static {v5, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->y(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v4

    .line 95
    goto/16 :goto_1

    .line 96
    .line 97
    :pswitch_3
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 98
    .line 99
    .line 100
    move-result v5

    .line 101
    if-eqz v5, :cond_0

    .line 102
    .line 103
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 104
    .line 105
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    invoke-static {v6, v5}, Lcom/google/crypto/tink/shaded/protobuf/b1;->y(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    if-eqz v5, :cond_0

    .line 118
    .line 119
    goto/16 :goto_1

    .line 120
    .line 121
    :pswitch_4
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 122
    .line 123
    .line 124
    move-result v5

    .line 125
    if-eqz v5, :cond_0

    .line 126
    .line 127
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 128
    .line 129
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 130
    .line 131
    .line 132
    move-result-wide v9

    .line 133
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 134
    .line 135
    .line 136
    move-result-wide v5

    .line 137
    cmp-long v5, v9, v5

    .line 138
    .line 139
    if-nez v5, :cond_0

    .line 140
    .line 141
    goto/16 :goto_1

    .line 142
    .line 143
    :pswitch_5
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    if-eqz v5, :cond_0

    .line 148
    .line 149
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 150
    .line 151
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 152
    .line 153
    .line 154
    move-result v6

    .line 155
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 156
    .line 157
    .line 158
    move-result v5

    .line 159
    if-ne v6, v5, :cond_0

    .line 160
    .line 161
    goto/16 :goto_1

    .line 162
    .line 163
    :pswitch_6
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 164
    .line 165
    .line 166
    move-result v5

    .line 167
    if-eqz v5, :cond_0

    .line 168
    .line 169
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 170
    .line 171
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 172
    .line 173
    .line 174
    move-result-wide v9

    .line 175
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 176
    .line 177
    .line 178
    move-result-wide v5

    .line 179
    cmp-long v5, v9, v5

    .line 180
    .line 181
    if-nez v5, :cond_0

    .line 182
    .line 183
    goto/16 :goto_1

    .line 184
    .line 185
    :pswitch_7
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    if-eqz v5, :cond_0

    .line 190
    .line 191
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 192
    .line 193
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 194
    .line 195
    .line 196
    move-result v6

    .line 197
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 198
    .line 199
    .line 200
    move-result v5

    .line 201
    if-ne v6, v5, :cond_0

    .line 202
    .line 203
    goto/16 :goto_1

    .line 204
    .line 205
    :pswitch_8
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 206
    .line 207
    .line 208
    move-result v5

    .line 209
    if-eqz v5, :cond_0

    .line 210
    .line 211
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 212
    .line 213
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 214
    .line 215
    .line 216
    move-result v6

    .line 217
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 218
    .line 219
    .line 220
    move-result v5

    .line 221
    if-ne v6, v5, :cond_0

    .line 222
    .line 223
    goto/16 :goto_1

    .line 224
    .line 225
    :pswitch_9
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 226
    .line 227
    .line 228
    move-result v5

    .line 229
    if-eqz v5, :cond_0

    .line 230
    .line 231
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 232
    .line 233
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 234
    .line 235
    .line 236
    move-result v6

    .line 237
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 238
    .line 239
    .line 240
    move-result v5

    .line 241
    if-ne v6, v5, :cond_0

    .line 242
    .line 243
    goto/16 :goto_1

    .line 244
    .line 245
    :pswitch_a
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 246
    .line 247
    .line 248
    move-result v5

    .line 249
    if-eqz v5, :cond_0

    .line 250
    .line 251
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 252
    .line 253
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v6

    .line 257
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v5

    .line 261
    invoke-static {v6, v5}, Lcom/google/crypto/tink/shaded/protobuf/b1;->y(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v5

    .line 265
    if-eqz v5, :cond_0

    .line 266
    .line 267
    goto/16 :goto_1

    .line 268
    .line 269
    :pswitch_b
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 270
    .line 271
    .line 272
    move-result v5

    .line 273
    if-eqz v5, :cond_0

    .line 274
    .line 275
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 276
    .line 277
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v6

    .line 281
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v5

    .line 285
    invoke-static {v6, v5}, Lcom/google/crypto/tink/shaded/protobuf/b1;->y(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result v5

    .line 289
    if-eqz v5, :cond_0

    .line 290
    .line 291
    goto/16 :goto_1

    .line 292
    .line 293
    :pswitch_c
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 294
    .line 295
    .line 296
    move-result v5

    .line 297
    if-eqz v5, :cond_0

    .line 298
    .line 299
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 300
    .line 301
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v6

    .line 305
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object v5

    .line 309
    invoke-static {v6, v5}, Lcom/google/crypto/tink/shaded/protobuf/b1;->y(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 310
    .line 311
    .line 312
    move-result v5

    .line 313
    if-eqz v5, :cond_0

    .line 314
    .line 315
    goto/16 :goto_1

    .line 316
    .line 317
    :pswitch_d
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 318
    .line 319
    .line 320
    move-result v5

    .line 321
    if-eqz v5, :cond_0

    .line 322
    .line 323
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 324
    .line 325
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->c(JLjava/lang/Object;)Z

    .line 326
    .line 327
    .line 328
    move-result v6

    .line 329
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->c(JLjava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v5

    .line 333
    if-ne v6, v5, :cond_0

    .line 334
    .line 335
    goto/16 :goto_1

    .line 336
    .line 337
    :pswitch_e
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 338
    .line 339
    .line 340
    move-result v5

    .line 341
    if-eqz v5, :cond_0

    .line 342
    .line 343
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 344
    .line 345
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 346
    .line 347
    .line 348
    move-result v6

    .line 349
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 350
    .line 351
    .line 352
    move-result v5

    .line 353
    if-ne v6, v5, :cond_0

    .line 354
    .line 355
    goto/16 :goto_1

    .line 356
    .line 357
    :pswitch_f
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 358
    .line 359
    .line 360
    move-result v5

    .line 361
    if-eqz v5, :cond_0

    .line 362
    .line 363
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 364
    .line 365
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 366
    .line 367
    .line 368
    move-result-wide v9

    .line 369
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 370
    .line 371
    .line 372
    move-result-wide v5

    .line 373
    cmp-long v5, v9, v5

    .line 374
    .line 375
    if-nez v5, :cond_0

    .line 376
    .line 377
    goto/16 :goto_1

    .line 378
    .line 379
    :pswitch_10
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 380
    .line 381
    .line 382
    move-result v5

    .line 383
    if-eqz v5, :cond_0

    .line 384
    .line 385
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 386
    .line 387
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 388
    .line 389
    .line 390
    move-result v6

    .line 391
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 392
    .line 393
    .line 394
    move-result v5

    .line 395
    if-ne v6, v5, :cond_0

    .line 396
    .line 397
    goto :goto_1

    .line 398
    :pswitch_11
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 399
    .line 400
    .line 401
    move-result v5

    .line 402
    if-eqz v5, :cond_0

    .line 403
    .line 404
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 405
    .line 406
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 407
    .line 408
    .line 409
    move-result-wide v9

    .line 410
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 411
    .line 412
    .line 413
    move-result-wide v5

    .line 414
    cmp-long v5, v9, v5

    .line 415
    .line 416
    if-nez v5, :cond_0

    .line 417
    .line 418
    goto :goto_1

    .line 419
    :pswitch_12
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 420
    .line 421
    .line 422
    move-result v5

    .line 423
    if-eqz v5, :cond_0

    .line 424
    .line 425
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 426
    .line 427
    invoke-virtual {v5, p1, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 428
    .line 429
    .line 430
    move-result-wide v9

    .line 431
    invoke-virtual {v5, p2, v7, v8}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 432
    .line 433
    .line 434
    move-result-wide v5

    .line 435
    cmp-long v5, v9, v5

    .line 436
    .line 437
    if-nez v5, :cond_0

    .line 438
    .line 439
    goto :goto_1

    .line 440
    :pswitch_13
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 441
    .line 442
    .line 443
    move-result v5

    .line 444
    if-eqz v5, :cond_0

    .line 445
    .line 446
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 447
    .line 448
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->f(JLjava/lang/Object;)F

    .line 449
    .line 450
    .line 451
    move-result v6

    .line 452
    invoke-static {v6}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 453
    .line 454
    .line 455
    move-result v6

    .line 456
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->f(JLjava/lang/Object;)F

    .line 457
    .line 458
    .line 459
    move-result v5

    .line 460
    invoke-static {v5}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 461
    .line 462
    .line 463
    move-result v5

    .line 464
    if-ne v6, v5, :cond_0

    .line 465
    .line 466
    goto :goto_1

    .line 467
    :pswitch_14
    invoke-virtual {p0, p1, p2, v3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z

    .line 468
    .line 469
    .line 470
    move-result v5

    .line 471
    if-eqz v5, :cond_0

    .line 472
    .line 473
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 474
    .line 475
    invoke-virtual {v5, v7, v8, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->e(JLjava/lang/Object;)D

    .line 476
    .line 477
    .line 478
    move-result-wide v9

    .line 479
    invoke-static {v9, v10}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 480
    .line 481
    .line 482
    move-result-wide v9

    .line 483
    invoke-virtual {v5, v7, v8, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->e(JLjava/lang/Object;)D

    .line 484
    .line 485
    .line 486
    move-result-wide v5

    .line 487
    invoke-static {v5, v6}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 488
    .line 489
    .line 490
    move-result-wide v5

    .line 491
    cmp-long v5, v9, v5

    .line 492
    .line 493
    if-nez v5, :cond_0

    .line 494
    .line 495
    :goto_1
    if-nez v4, :cond_1

    .line 496
    .line 497
    goto :goto_2

    .line 498
    :cond_1
    add-int/lit8 v3, v3, 0x3

    .line 499
    .line 500
    goto/16 :goto_0

    .line 501
    .line 502
    :cond_2
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 503
    .line 504
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 505
    .line 506
    .line 507
    iget-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 508
    .line 509
    iget-object p1, p2, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 510
    .line 511
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/c1;->equals(Ljava/lang/Object;)Z

    .line 512
    .line 513
    .line 514
    move-result p0

    .line 515
    if-nez p0, :cond_3

    .line 516
    .line 517
    :goto_2
    return v2

    .line 518
    :cond_3
    return v4

    .line 519
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public final h(Lcom/google/crypto/tink/shaded/protobuf/x;)I
    .locals 11

    .line 1
    iget-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x0

    .line 5
    move v3, v2

    .line 6
    :goto_0
    if-ge v2, v1, :cond_3

    .line 7
    .line 8
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 9
    .line 10
    .line 11
    move-result v4

    .line 12
    aget v5, v0, v2

    .line 13
    .line 14
    const v6, 0xfffff

    .line 15
    .line 16
    .line 17
    and-int/2addr v6, v4

    .line 18
    int-to-long v6, v6

    .line 19
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    const/16 v8, 0x4d5

    .line 24
    .line 25
    const/16 v9, 0x4cf

    .line 26
    .line 27
    const/16 v10, 0x25

    .line 28
    .line 29
    packed-switch v4, :pswitch_data_0

    .line 30
    .line 31
    .line 32
    goto/16 :goto_4

    .line 33
    .line 34
    :pswitch_0
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_2

    .line 39
    .line 40
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 41
    .line 42
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    mul-int/lit8 v3, v3, 0x35

    .line 47
    .line 48
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    :goto_1
    add-int/2addr v4, v3

    .line 53
    move v3, v4

    .line 54
    goto/16 :goto_4

    .line 55
    .line 56
    :pswitch_1
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-eqz v4, :cond_2

    .line 61
    .line 62
    mul-int/lit8 v3, v3, 0x35

    .line 63
    .line 64
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 65
    .line 66
    .line 67
    move-result-wide v4

    .line 68
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    goto :goto_1

    .line 73
    :pswitch_2
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eqz v4, :cond_2

    .line 78
    .line 79
    mul-int/lit8 v3, v3, 0x35

    .line 80
    .line 81
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 82
    .line 83
    .line 84
    move-result v4

    .line 85
    goto :goto_1

    .line 86
    :pswitch_3
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    if-eqz v4, :cond_2

    .line 91
    .line 92
    mul-int/lit8 v3, v3, 0x35

    .line 93
    .line 94
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 95
    .line 96
    .line 97
    move-result-wide v4

    .line 98
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    goto :goto_1

    .line 103
    :pswitch_4
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    if-eqz v4, :cond_2

    .line 108
    .line 109
    mul-int/lit8 v3, v3, 0x35

    .line 110
    .line 111
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 112
    .line 113
    .line 114
    move-result v4

    .line 115
    goto :goto_1

    .line 116
    :pswitch_5
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 117
    .line 118
    .line 119
    move-result v4

    .line 120
    if-eqz v4, :cond_2

    .line 121
    .line 122
    mul-int/lit8 v3, v3, 0x35

    .line 123
    .line 124
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    goto :goto_1

    .line 129
    :pswitch_6
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    if-eqz v4, :cond_2

    .line 134
    .line 135
    mul-int/lit8 v3, v3, 0x35

    .line 136
    .line 137
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    goto :goto_1

    .line 142
    :pswitch_7
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    if-eqz v4, :cond_2

    .line 147
    .line 148
    mul-int/lit8 v3, v3, 0x35

    .line 149
    .line 150
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 151
    .line 152
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v4

    .line 156
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    goto :goto_1

    .line 161
    :pswitch_8
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    if-eqz v4, :cond_2

    .line 166
    .line 167
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 168
    .line 169
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v4

    .line 173
    mul-int/lit8 v3, v3, 0x35

    .line 174
    .line 175
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 176
    .line 177
    .line 178
    move-result v4

    .line 179
    goto :goto_1

    .line 180
    :pswitch_9
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    if-eqz v4, :cond_2

    .line 185
    .line 186
    mul-int/lit8 v3, v3, 0x35

    .line 187
    .line 188
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 189
    .line 190
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    check-cast v4, Ljava/lang/String;

    .line 195
    .line 196
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 197
    .line 198
    .line 199
    move-result v4

    .line 200
    goto/16 :goto_1

    .line 201
    .line 202
    :pswitch_a
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 203
    .line 204
    .line 205
    move-result v4

    .line 206
    if-eqz v4, :cond_2

    .line 207
    .line 208
    mul-int/lit8 v3, v3, 0x35

    .line 209
    .line 210
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 211
    .line 212
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v4

    .line 216
    check-cast v4, Ljava/lang/Boolean;

    .line 217
    .line 218
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 219
    .line 220
    .line 221
    move-result v4

    .line 222
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 223
    .line 224
    if-eqz v4, :cond_0

    .line 225
    .line 226
    :goto_2
    move v8, v9

    .line 227
    :cond_0
    add-int/2addr v8, v3

    .line 228
    move v3, v8

    .line 229
    goto/16 :goto_4

    .line 230
    .line 231
    :pswitch_b
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 232
    .line 233
    .line 234
    move-result v4

    .line 235
    if-eqz v4, :cond_2

    .line 236
    .line 237
    mul-int/lit8 v3, v3, 0x35

    .line 238
    .line 239
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 240
    .line 241
    .line 242
    move-result v4

    .line 243
    goto/16 :goto_1

    .line 244
    .line 245
    :pswitch_c
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    if-eqz v4, :cond_2

    .line 250
    .line 251
    mul-int/lit8 v3, v3, 0x35

    .line 252
    .line 253
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 254
    .line 255
    .line 256
    move-result-wide v4

    .line 257
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 258
    .line 259
    .line 260
    move-result v4

    .line 261
    goto/16 :goto_1

    .line 262
    .line 263
    :pswitch_d
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 264
    .line 265
    .line 266
    move-result v4

    .line 267
    if-eqz v4, :cond_2

    .line 268
    .line 269
    mul-int/lit8 v3, v3, 0x35

    .line 270
    .line 271
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 272
    .line 273
    .line 274
    move-result v4

    .line 275
    goto/16 :goto_1

    .line 276
    .line 277
    :pswitch_e
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 278
    .line 279
    .line 280
    move-result v4

    .line 281
    if-eqz v4, :cond_2

    .line 282
    .line 283
    mul-int/lit8 v3, v3, 0x35

    .line 284
    .line 285
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 286
    .line 287
    .line 288
    move-result-wide v4

    .line 289
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 290
    .line 291
    .line 292
    move-result v4

    .line 293
    goto/16 :goto_1

    .line 294
    .line 295
    :pswitch_f
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 296
    .line 297
    .line 298
    move-result v4

    .line 299
    if-eqz v4, :cond_2

    .line 300
    .line 301
    mul-int/lit8 v3, v3, 0x35

    .line 302
    .line 303
    invoke-static {v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 304
    .line 305
    .line 306
    move-result-wide v4

    .line 307
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 308
    .line 309
    .line 310
    move-result v4

    .line 311
    goto/16 :goto_1

    .line 312
    .line 313
    :pswitch_10
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 314
    .line 315
    .line 316
    move-result v4

    .line 317
    if-eqz v4, :cond_2

    .line 318
    .line 319
    mul-int/lit8 v3, v3, 0x35

    .line 320
    .line 321
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 322
    .line 323
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v4

    .line 327
    check-cast v4, Ljava/lang/Float;

    .line 328
    .line 329
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 330
    .line 331
    .line 332
    move-result v4

    .line 333
    invoke-static {v4}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 334
    .line 335
    .line 336
    move-result v4

    .line 337
    goto/16 :goto_1

    .line 338
    .line 339
    :pswitch_11
    invoke-virtual {p0, v5, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 340
    .line 341
    .line 342
    move-result v4

    .line 343
    if-eqz v4, :cond_2

    .line 344
    .line 345
    mul-int/lit8 v3, v3, 0x35

    .line 346
    .line 347
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 348
    .line 349
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v4

    .line 353
    check-cast v4, Ljava/lang/Double;

    .line 354
    .line 355
    invoke-virtual {v4}, Ljava/lang/Double;->doubleValue()D

    .line 356
    .line 357
    .line 358
    move-result-wide v4

    .line 359
    invoke-static {v4, v5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 360
    .line 361
    .line 362
    move-result-wide v4

    .line 363
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 364
    .line 365
    .line 366
    move-result v4

    .line 367
    goto/16 :goto_1

    .line 368
    .line 369
    :pswitch_12
    mul-int/lit8 v3, v3, 0x35

    .line 370
    .line 371
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 372
    .line 373
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v4

    .line 377
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 378
    .line 379
    .line 380
    move-result v4

    .line 381
    goto/16 :goto_1

    .line 382
    .line 383
    :pswitch_13
    mul-int/lit8 v3, v3, 0x35

    .line 384
    .line 385
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 386
    .line 387
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v4

    .line 391
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 392
    .line 393
    .line 394
    move-result v4

    .line 395
    goto/16 :goto_1

    .line 396
    .line 397
    :pswitch_14
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 398
    .line 399
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v4

    .line 403
    if-eqz v4, :cond_1

    .line 404
    .line 405
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 406
    .line 407
    .line 408
    move-result v10

    .line 409
    :cond_1
    :goto_3
    mul-int/lit8 v3, v3, 0x35

    .line 410
    .line 411
    add-int/2addr v3, v10

    .line 412
    goto/16 :goto_4

    .line 413
    .line 414
    :pswitch_15
    mul-int/lit8 v3, v3, 0x35

    .line 415
    .line 416
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 417
    .line 418
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 419
    .line 420
    .line 421
    move-result-wide v4

    .line 422
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 423
    .line 424
    .line 425
    move-result v4

    .line 426
    goto/16 :goto_1

    .line 427
    .line 428
    :pswitch_16
    mul-int/lit8 v3, v3, 0x35

    .line 429
    .line 430
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 431
    .line 432
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 433
    .line 434
    .line 435
    move-result v4

    .line 436
    goto/16 :goto_1

    .line 437
    .line 438
    :pswitch_17
    mul-int/lit8 v3, v3, 0x35

    .line 439
    .line 440
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 441
    .line 442
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 443
    .line 444
    .line 445
    move-result-wide v4

    .line 446
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 447
    .line 448
    .line 449
    move-result v4

    .line 450
    goto/16 :goto_1

    .line 451
    .line 452
    :pswitch_18
    mul-int/lit8 v3, v3, 0x35

    .line 453
    .line 454
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 455
    .line 456
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 457
    .line 458
    .line 459
    move-result v4

    .line 460
    goto/16 :goto_1

    .line 461
    .line 462
    :pswitch_19
    mul-int/lit8 v3, v3, 0x35

    .line 463
    .line 464
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 465
    .line 466
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 467
    .line 468
    .line 469
    move-result v4

    .line 470
    goto/16 :goto_1

    .line 471
    .line 472
    :pswitch_1a
    mul-int/lit8 v3, v3, 0x35

    .line 473
    .line 474
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 475
    .line 476
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 477
    .line 478
    .line 479
    move-result v4

    .line 480
    goto/16 :goto_1

    .line 481
    .line 482
    :pswitch_1b
    mul-int/lit8 v3, v3, 0x35

    .line 483
    .line 484
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 485
    .line 486
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v4

    .line 490
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 491
    .line 492
    .line 493
    move-result v4

    .line 494
    goto/16 :goto_1

    .line 495
    .line 496
    :pswitch_1c
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 497
    .line 498
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    move-result-object v4

    .line 502
    if-eqz v4, :cond_1

    .line 503
    .line 504
    invoke-virtual {v4}, Ljava/lang/Object;->hashCode()I

    .line 505
    .line 506
    .line 507
    move-result v10

    .line 508
    goto :goto_3

    .line 509
    :pswitch_1d
    mul-int/lit8 v3, v3, 0x35

    .line 510
    .line 511
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 512
    .line 513
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v4

    .line 517
    check-cast v4, Ljava/lang/String;

    .line 518
    .line 519
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 520
    .line 521
    .line 522
    move-result v4

    .line 523
    goto/16 :goto_1

    .line 524
    .line 525
    :pswitch_1e
    mul-int/lit8 v3, v3, 0x35

    .line 526
    .line 527
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 528
    .line 529
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->c(JLjava/lang/Object;)Z

    .line 530
    .line 531
    .line 532
    move-result v4

    .line 533
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/b0;->a:Ljava/nio/charset/Charset;

    .line 534
    .line 535
    if-eqz v4, :cond_0

    .line 536
    .line 537
    goto/16 :goto_2

    .line 538
    .line 539
    :pswitch_1f
    mul-int/lit8 v3, v3, 0x35

    .line 540
    .line 541
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 542
    .line 543
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 544
    .line 545
    .line 546
    move-result v4

    .line 547
    goto/16 :goto_1

    .line 548
    .line 549
    :pswitch_20
    mul-int/lit8 v3, v3, 0x35

    .line 550
    .line 551
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 552
    .line 553
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 554
    .line 555
    .line 556
    move-result-wide v4

    .line 557
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 558
    .line 559
    .line 560
    move-result v4

    .line 561
    goto/16 :goto_1

    .line 562
    .line 563
    :pswitch_21
    mul-int/lit8 v3, v3, 0x35

    .line 564
    .line 565
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 566
    .line 567
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 568
    .line 569
    .line 570
    move-result v4

    .line 571
    goto/16 :goto_1

    .line 572
    .line 573
    :pswitch_22
    mul-int/lit8 v3, v3, 0x35

    .line 574
    .line 575
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 576
    .line 577
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 578
    .line 579
    .line 580
    move-result-wide v4

    .line 581
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 582
    .line 583
    .line 584
    move-result v4

    .line 585
    goto/16 :goto_1

    .line 586
    .line 587
    :pswitch_23
    mul-int/lit8 v3, v3, 0x35

    .line 588
    .line 589
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 590
    .line 591
    invoke-virtual {v4, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 592
    .line 593
    .line 594
    move-result-wide v4

    .line 595
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 596
    .line 597
    .line 598
    move-result v4

    .line 599
    goto/16 :goto_1

    .line 600
    .line 601
    :pswitch_24
    mul-int/lit8 v3, v3, 0x35

    .line 602
    .line 603
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 604
    .line 605
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->f(JLjava/lang/Object;)F

    .line 606
    .line 607
    .line 608
    move-result v4

    .line 609
    invoke-static {v4}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 610
    .line 611
    .line 612
    move-result v4

    .line 613
    goto/16 :goto_1

    .line 614
    .line 615
    :pswitch_25
    mul-int/lit8 v3, v3, 0x35

    .line 616
    .line 617
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 618
    .line 619
    invoke-virtual {v4, v6, v7, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->e(JLjava/lang/Object;)D

    .line 620
    .line 621
    .line 622
    move-result-wide v4

    .line 623
    invoke-static {v4, v5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 624
    .line 625
    .line 626
    move-result-wide v4

    .line 627
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b0;->b(J)I

    .line 628
    .line 629
    .line 630
    move-result v4

    .line 631
    goto/16 :goto_1

    .line 632
    .line 633
    :cond_2
    :goto_4
    add-int/lit8 v2, v2, 0x3

    .line 634
    .line 635
    goto/16 :goto_0

    .line 636
    .line 637
    :cond_3
    mul-int/lit8 v3, v3, 0x35

    .line 638
    .line 639
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 640
    .line 641
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 642
    .line 643
    .line 644
    iget-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 645
    .line 646
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/c1;->hashCode()I

    .line 647
    .line 648
    .line 649
    move-result p0

    .line 650
    add-int/2addr p0, v3

    .line 651
    return p0

    .line 652
    nop

    .line 653
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final i(Lcom/google/crypto/tink/shaded/protobuf/a;)I
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->q(Ljava/lang/Object;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->p(Ljava/lang/Object;)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public final j(Lcom/google/crypto/tink/shaded/protobuf/x;Lcom/google/crypto/tink/shaded/protobuf/x;)V
    .locals 10

    .line 1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    :goto_0
    iget-object v1, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 6
    .line 7
    array-length v2, v1

    .line 8
    if-ge v0, v2, :cond_1

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const v3, 0xfffff

    .line 15
    .line 16
    .line 17
    and-int/2addr v3, v2

    .line 18
    int-to-long v6, v3

    .line 19
    aget v1, v1, v0

    .line 20
    .line 21
    invoke-static {v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    packed-switch v2, :pswitch_data_0

    .line 26
    .line 27
    .line 28
    goto :goto_1

    .line 29
    :pswitch_0
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->w(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    :goto_1
    move-object v5, p1

    .line 33
    goto/16 :goto_2

    .line 34
    .line 35
    :pswitch_1
    invoke-virtual {p0, v1, p2, v0}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_0

    .line 40
    .line 41
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 42
    .line 43
    invoke-virtual {v2, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-static {p1, v6, v7, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0, v1, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 51
    .line 52
    .line 53
    goto :goto_1

    .line 54
    :pswitch_2
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->w(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :pswitch_3
    invoke-virtual {p0, v1, p2, v0}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_0

    .line 63
    .line 64
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 65
    .line 66
    invoke-virtual {v2, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-static {p1, v6, v7, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, v1, p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :pswitch_4
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 78
    .line 79
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 80
    .line 81
    invoke-virtual {v1, p1, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    invoke-virtual {v1, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    iget-object v3, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 90
    .line 91
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    invoke-static {v2, v1}, Lcom/google/crypto/tink/shaded/protobuf/n0;->b(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-static {p1, v6, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :pswitch_5
    iget-object v1, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->l:Lcom/google/crypto/tink/shaded/protobuf/j0;

    .line 103
    .line 104
    invoke-virtual {v1, p1, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/j0;->b(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :pswitch_6
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->v(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    goto :goto_1

    .line 112
    :pswitch_7
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-eqz v1, :cond_0

    .line 117
    .line 118
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 119
    .line 120
    invoke-virtual {v1, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 121
    .line 122
    .line 123
    move-result-wide v1

    .line 124
    invoke-static {v6, v7, p1, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    goto :goto_1

    .line 131
    :pswitch_8
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_0

    .line 136
    .line 137
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 138
    .line 139
    invoke-virtual {v1, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    invoke-static {v6, v7, p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    goto :goto_1

    .line 150
    :pswitch_9
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    if-eqz v1, :cond_0

    .line 155
    .line 156
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 157
    .line 158
    invoke-virtual {v1, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 159
    .line 160
    .line 161
    move-result-wide v1

    .line 162
    invoke-static {v6, v7, p1, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    goto/16 :goto_1

    .line 169
    .line 170
    :pswitch_a
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    if-eqz v1, :cond_0

    .line 175
    .line 176
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 177
    .line 178
    invoke-virtual {v1, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    invoke-static {v6, v7, p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    goto/16 :goto_1

    .line 189
    .line 190
    :pswitch_b
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v1

    .line 194
    if-eqz v1, :cond_0

    .line 195
    .line 196
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 197
    .line 198
    invoke-virtual {v1, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 199
    .line 200
    .line 201
    move-result v1

    .line 202
    invoke-static {v6, v7, p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    goto/16 :goto_1

    .line 209
    .line 210
    :pswitch_c
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v1

    .line 214
    if-eqz v1, :cond_0

    .line 215
    .line 216
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 217
    .line 218
    invoke-virtual {v1, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 219
    .line 220
    .line 221
    move-result v1

    .line 222
    invoke-static {v6, v7, p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    goto/16 :goto_1

    .line 229
    .line 230
    :pswitch_d
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 231
    .line 232
    .line 233
    move-result v1

    .line 234
    if-eqz v1, :cond_0

    .line 235
    .line 236
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 237
    .line 238
    invoke-virtual {v1, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    invoke-static {p1, v6, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    goto/16 :goto_1

    .line 249
    .line 250
    :pswitch_e
    invoke-virtual {p0, v0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->v(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 251
    .line 252
    .line 253
    goto/16 :goto_1

    .line 254
    .line 255
    :pswitch_f
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    move-result v1

    .line 259
    if-eqz v1, :cond_0

    .line 260
    .line 261
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 262
    .line 263
    invoke-virtual {v1, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v1

    .line 267
    invoke-static {p1, v6, v7, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 271
    .line 272
    .line 273
    goto/16 :goto_1

    .line 274
    .line 275
    :pswitch_10
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v1

    .line 279
    if-eqz v1, :cond_0

    .line 280
    .line 281
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 282
    .line 283
    invoke-virtual {v1, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->c(JLjava/lang/Object;)Z

    .line 284
    .line 285
    .line 286
    move-result v2

    .line 287
    invoke-virtual {v1, p1, v6, v7, v2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->k(Ljava/lang/Object;JZ)V

    .line 288
    .line 289
    .line 290
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    goto/16 :goto_1

    .line 294
    .line 295
    :pswitch_11
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 296
    .line 297
    .line 298
    move-result v1

    .line 299
    if-eqz v1, :cond_0

    .line 300
    .line 301
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 302
    .line 303
    invoke-virtual {v1, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 304
    .line 305
    .line 306
    move-result v1

    .line 307
    invoke-static {v6, v7, p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    goto/16 :goto_1

    .line 314
    .line 315
    :pswitch_12
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    move-result v1

    .line 319
    if-eqz v1, :cond_0

    .line 320
    .line 321
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 322
    .line 323
    invoke-virtual {v1, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 324
    .line 325
    .line 326
    move-result-wide v1

    .line 327
    invoke-static {v6, v7, p1, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 331
    .line 332
    .line 333
    goto/16 :goto_1

    .line 334
    .line 335
    :pswitch_13
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 336
    .line 337
    .line 338
    move-result v1

    .line 339
    if-eqz v1, :cond_0

    .line 340
    .line 341
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 342
    .line 343
    invoke-virtual {v1, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 344
    .line 345
    .line 346
    move-result v1

    .line 347
    invoke-static {v6, v7, p1, v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 348
    .line 349
    .line 350
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 351
    .line 352
    .line 353
    goto/16 :goto_1

    .line 354
    .line 355
    :pswitch_14
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    move-result v1

    .line 359
    if-eqz v1, :cond_0

    .line 360
    .line 361
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 362
    .line 363
    invoke-virtual {v1, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 364
    .line 365
    .line 366
    move-result-wide v1

    .line 367
    invoke-static {v6, v7, p1, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 368
    .line 369
    .line 370
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 371
    .line 372
    .line 373
    goto/16 :goto_1

    .line 374
    .line 375
    :pswitch_15
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 376
    .line 377
    .line 378
    move-result v1

    .line 379
    if-eqz v1, :cond_0

    .line 380
    .line 381
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 382
    .line 383
    invoke-virtual {v1, p2, v6, v7}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 384
    .line 385
    .line 386
    move-result-wide v1

    .line 387
    invoke-static {v6, v7, p1, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->n(JLjava/lang/Object;J)V

    .line 388
    .line 389
    .line 390
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 391
    .line 392
    .line 393
    goto/16 :goto_1

    .line 394
    .line 395
    :pswitch_16
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 396
    .line 397
    .line 398
    move-result v1

    .line 399
    if-eqz v1, :cond_0

    .line 400
    .line 401
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 402
    .line 403
    invoke-virtual {v1, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->f(JLjava/lang/Object;)F

    .line 404
    .line 405
    .line 406
    move-result v2

    .line 407
    invoke-virtual {v1, p1, v6, v7, v2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->n(Ljava/lang/Object;JF)V

    .line 408
    .line 409
    .line 410
    invoke-virtual {p0, v0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 411
    .line 412
    .line 413
    goto/16 :goto_1

    .line 414
    .line 415
    :pswitch_17
    invoke-virtual {p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 416
    .line 417
    .line 418
    move-result v1

    .line 419
    if-eqz v1, :cond_0

    .line 420
    .line 421
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 422
    .line 423
    invoke-virtual {v4, v6, v7, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->e(JLjava/lang/Object;)D

    .line 424
    .line 425
    .line 426
    move-result-wide v8

    .line 427
    move-object v5, p1

    .line 428
    invoke-virtual/range {v4 .. v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->m(Ljava/lang/Object;JD)V

    .line 429
    .line 430
    .line 431
    invoke-virtual {p0, v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 432
    .line 433
    .line 434
    :goto_2
    add-int/lit8 v0, v0, 0x3

    .line 435
    .line 436
    move-object p1, v5

    .line 437
    goto/16 :goto_0

    .line 438
    .line 439
    :cond_1
    move-object v5, p1

    .line 440
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 441
    .line 442
    invoke-static {p0, v5, p2}, Lcom/google/crypto/tink/shaded/protobuf/b1;->x(Lcom/google/crypto/tink/shaded/protobuf/d1;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 443
    .line 444
    .line 445
    return-void

    .line 446
    nop

    .line 447
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final k(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/Object;I)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p3, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-virtual {p0, p3, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-ne p1, p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final l(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object p3, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 2
    .line 3
    aget p3, p3, p1

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 6
    .line 7
    .line 8
    move-result p3

    .line 9
    const v0, 0xfffff

    .line 10
    .line 11
    .line 12
    and-int/2addr p3, v0

    .line 13
    int-to-long v0, p3

    .line 14
    sget-object p3, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 15
    .line 16
    invoke-virtual {p3, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    if-nez p2, :cond_0

    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->m(I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public final m(I)V
    .locals 3

    .line 1
    const/4 v0, 0x2

    .line 2
    const/4 v1, 0x1

    .line 3
    const/4 v2, 0x3

    .line 4
    invoke-static {p1, v2, v0, v1}, La7/g0;->d(IIII)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->b:[Ljava/lang/Object;

    .line 9
    .line 10
    aget-object p0, p0, p1

    .line 11
    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/ClassCastException;

    .line 16
    .line 17
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public final n(I)Ljava/lang/Object;
    .locals 0

    .line 1
    div-int/lit8 p1, p1, 0x3

    .line 2
    .line 3
    mul-int/lit8 p1, p1, 0x2

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->b:[Ljava/lang/Object;

    .line 6
    .line 7
    aget-object p0, p0, p1

    .line 8
    .line 9
    return-object p0
.end method

.method public final o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;
    .locals 2

    .line 1
    div-int/lit8 p1, p1, 0x3

    .line 2
    .line 3
    mul-int/lit8 p1, p1, 0x2

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->b:[Ljava/lang/Object;

    .line 6
    .line 7
    aget-object v0, p0, p1

    .line 8
    .line 9
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 15
    .line 16
    add-int/lit8 v1, p1, 0x1

    .line 17
    .line 18
    aget-object v1, p0, v1

    .line 19
    .line 20
    check-cast v1, Ljava/lang/Class;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    aput-object v0, p0, p1

    .line 27
    .line 28
    return-object v0
.end method

.method public final p(Ljava/lang/Object;)I
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 6
    .line 7
    const/4 v4, -0x1

    .line 8
    move v7, v4

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v6, 0x0

    .line 11
    const/4 v8, 0x0

    .line 12
    :goto_0
    iget-object v9, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 13
    .line 14
    array-length v10, v9

    .line 15
    if-ge v5, v10, :cond_a

    .line 16
    .line 17
    invoke-virtual {v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 18
    .line 19
    .line 20
    move-result v10

    .line 21
    aget v11, v9, v5

    .line 22
    .line 23
    invoke-static {v10}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 24
    .line 25
    .line 26
    move-result v12

    .line 27
    const/16 v13, 0x11

    .line 28
    .line 29
    const v14, 0xfffff

    .line 30
    .line 31
    .line 32
    const/4 v15, 0x1

    .line 33
    if-gt v12, v13, :cond_0

    .line 34
    .line 35
    add-int/lit8 v13, v5, 0x2

    .line 36
    .line 37
    aget v9, v9, v13

    .line 38
    .line 39
    and-int v13, v9, v14

    .line 40
    .line 41
    ushr-int/lit8 v9, v9, 0x14

    .line 42
    .line 43
    shl-int v9, v15, v9

    .line 44
    .line 45
    if-eq v13, v7, :cond_1

    .line 46
    .line 47
    int-to-long v7, v13

    .line 48
    invoke-virtual {v2, v1, v7, v8}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 49
    .line 50
    .line 51
    move-result v8

    .line 52
    move v7, v13

    .line 53
    goto :goto_1

    .line 54
    :cond_0
    const/4 v9, 0x0

    .line 55
    :cond_1
    :goto_1
    and-int/2addr v10, v14

    .line 56
    int-to-long v13, v10

    .line 57
    const/4 v3, 0x4

    .line 58
    const/16 v16, 0x3f

    .line 59
    .line 60
    const/16 v10, 0x8

    .line 61
    .line 62
    packed-switch v12, :pswitch_data_0

    .line 63
    .line 64
    .line 65
    goto/16 :goto_a

    .line 66
    .line 67
    :pswitch_0
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-eqz v3, :cond_9

    .line 72
    .line 73
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 78
    .line 79
    invoke-virtual {v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 80
    .line 81
    .line 82
    move-result-object v9

    .line 83
    invoke-static {v11, v3, v9}, Lcom/google/crypto/tink/shaded/protobuf/k;->D(ILcom/google/crypto/tink/shaded/protobuf/a;Lcom/google/crypto/tink/shaded/protobuf/a1;)I

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    :goto_2
    add-int/2addr v6, v3

    .line 88
    goto/16 :goto_a

    .line 89
    .line 90
    :pswitch_1
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 91
    .line 92
    .line 93
    move-result v3

    .line 94
    if-eqz v3, :cond_9

    .line 95
    .line 96
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 97
    .line 98
    .line 99
    move-result-wide v9

    .line 100
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 101
    .line 102
    .line 103
    move-result v3

    .line 104
    shl-long v11, v9, v15

    .line 105
    .line 106
    shr-long v9, v9, v16

    .line 107
    .line 108
    xor-long/2addr v9, v11

    .line 109
    invoke-static {v9, v10}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 110
    .line 111
    .line 112
    move-result v9

    .line 113
    :goto_3
    add-int/2addr v9, v3

    .line 114
    :goto_4
    add-int/2addr v6, v9

    .line 115
    goto/16 :goto_a

    .line 116
    .line 117
    :pswitch_2
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    if-eqz v3, :cond_9

    .line 122
    .line 123
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 124
    .line 125
    .line 126
    move-result v3

    .line 127
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 128
    .line 129
    .line 130
    move-result v9

    .line 131
    shl-int/lit8 v10, v3, 0x1

    .line 132
    .line 133
    shr-int/lit8 v3, v3, 0x1f

    .line 134
    .line 135
    xor-int/2addr v3, v10

    .line 136
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 137
    .line 138
    .line 139
    move-result v3

    .line 140
    :goto_5
    add-int/2addr v3, v9

    .line 141
    goto :goto_2

    .line 142
    :pswitch_3
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 143
    .line 144
    .line 145
    move-result v3

    .line 146
    if-eqz v3, :cond_9

    .line 147
    .line 148
    invoke-static {v11, v10, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 149
    .line 150
    .line 151
    move-result v6

    .line 152
    goto/16 :goto_a

    .line 153
    .line 154
    :pswitch_4
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 155
    .line 156
    .line 157
    move-result v9

    .line 158
    if-eqz v9, :cond_9

    .line 159
    .line 160
    invoke-static {v11, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 161
    .line 162
    .line 163
    move-result v6

    .line 164
    goto/16 :goto_a

    .line 165
    .line 166
    :pswitch_5
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    if-eqz v3, :cond_9

    .line 171
    .line 172
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 173
    .line 174
    .line 175
    move-result v3

    .line 176
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 177
    .line 178
    .line 179
    move-result v9

    .line 180
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->E(I)I

    .line 181
    .line 182
    .line 183
    move-result v3

    .line 184
    goto :goto_5

    .line 185
    :pswitch_6
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 186
    .line 187
    .line 188
    move-result v3

    .line 189
    if-eqz v3, :cond_9

    .line 190
    .line 191
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 192
    .line 193
    .line 194
    move-result v3

    .line 195
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 196
    .line 197
    .line 198
    move-result v9

    .line 199
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 200
    .line 201
    .line 202
    move-result v3

    .line 203
    goto :goto_5

    .line 204
    :pswitch_7
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 205
    .line 206
    .line 207
    move-result v3

    .line 208
    if-eqz v3, :cond_9

    .line 209
    .line 210
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v3

    .line 214
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 215
    .line 216
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->z(ILcom/google/crypto/tink/shaded/protobuf/i;)I

    .line 217
    .line 218
    .line 219
    move-result v3

    .line 220
    goto/16 :goto_2

    .line 221
    .line 222
    :pswitch_8
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 223
    .line 224
    .line 225
    move-result v3

    .line 226
    if-eqz v3, :cond_9

    .line 227
    .line 228
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v3

    .line 232
    invoke-virtual {v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 233
    .line 234
    .line 235
    move-result-object v9

    .line 236
    sget-object v10, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 237
    .line 238
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 239
    .line 240
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 241
    .line 242
    .line 243
    move-result v10

    .line 244
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 245
    .line 246
    .line 247
    move-object v11, v3

    .line 248
    check-cast v11, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 249
    .line 250
    iget v12, v11, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 251
    .line 252
    if-ne v12, v4, :cond_2

    .line 253
    .line 254
    invoke-interface {v9, v3}, Lcom/google/crypto/tink/shaded/protobuf/a1;->i(Lcom/google/crypto/tink/shaded/protobuf/a;)I

    .line 255
    .line 256
    .line 257
    move-result v12

    .line 258
    iput v12, v11, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 259
    .line 260
    :cond_2
    invoke-static {v12, v12, v10, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 261
    .line 262
    .line 263
    move-result v6

    .line 264
    goto/16 :goto_a

    .line 265
    .line 266
    :pswitch_9
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 267
    .line 268
    .line 269
    move-result v3

    .line 270
    if-eqz v3, :cond_9

    .line 271
    .line 272
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v3

    .line 276
    instance-of v9, v3, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 277
    .line 278
    if-eqz v9, :cond_3

    .line 279
    .line 280
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 281
    .line 282
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 283
    .line 284
    .line 285
    move-result v9

    .line 286
    invoke-virtual {v3}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 287
    .line 288
    .line 289
    move-result v3

    .line 290
    invoke-static {v3, v3, v9, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 291
    .line 292
    .line 293
    move-result v3

    .line 294
    :goto_6
    move v6, v3

    .line 295
    goto/16 :goto_a

    .line 296
    .line 297
    :cond_3
    check-cast v3, Ljava/lang/String;

    .line 298
    .line 299
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 300
    .line 301
    .line 302
    move-result v9

    .line 303
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->F(Ljava/lang/String;)I

    .line 304
    .line 305
    .line 306
    move-result v3

    .line 307
    :goto_7
    add-int/2addr v3, v9

    .line 308
    add-int/2addr v3, v6

    .line 309
    goto :goto_6

    .line 310
    :pswitch_a
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 311
    .line 312
    .line 313
    move-result v3

    .line 314
    if-eqz v3, :cond_9

    .line 315
    .line 316
    invoke-static {v11, v15, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 317
    .line 318
    .line 319
    move-result v6

    .line 320
    goto/16 :goto_a

    .line 321
    .line 322
    :pswitch_b
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 323
    .line 324
    .line 325
    move-result v3

    .line 326
    if-eqz v3, :cond_9

    .line 327
    .line 328
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->B(I)I

    .line 329
    .line 330
    .line 331
    move-result v3

    .line 332
    goto/16 :goto_2

    .line 333
    .line 334
    :pswitch_c
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 335
    .line 336
    .line 337
    move-result v3

    .line 338
    if-eqz v3, :cond_9

    .line 339
    .line 340
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->C(I)I

    .line 341
    .line 342
    .line 343
    move-result v3

    .line 344
    goto/16 :goto_2

    .line 345
    .line 346
    :pswitch_d
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 347
    .line 348
    .line 349
    move-result v3

    .line 350
    if-eqz v3, :cond_9

    .line 351
    .line 352
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 353
    .line 354
    .line 355
    move-result v3

    .line 356
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 357
    .line 358
    .line 359
    move-result v9

    .line 360
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->E(I)I

    .line 361
    .line 362
    .line 363
    move-result v3

    .line 364
    goto/16 :goto_5

    .line 365
    .line 366
    :pswitch_e
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 367
    .line 368
    .line 369
    move-result v3

    .line 370
    if-eqz v3, :cond_9

    .line 371
    .line 372
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 373
    .line 374
    .line 375
    move-result-wide v9

    .line 376
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 377
    .line 378
    .line 379
    move-result v3

    .line 380
    invoke-static {v9, v10}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 381
    .line 382
    .line 383
    move-result v9

    .line 384
    goto/16 :goto_3

    .line 385
    .line 386
    :pswitch_f
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 387
    .line 388
    .line 389
    move-result v3

    .line 390
    if-eqz v3, :cond_9

    .line 391
    .line 392
    invoke-static {v13, v14, v1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 393
    .line 394
    .line 395
    move-result-wide v9

    .line 396
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 397
    .line 398
    .line 399
    move-result v3

    .line 400
    invoke-static {v9, v10}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 401
    .line 402
    .line 403
    move-result v9

    .line 404
    goto/16 :goto_3

    .line 405
    .line 406
    :pswitch_10
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 407
    .line 408
    .line 409
    move-result v9

    .line 410
    if-eqz v9, :cond_9

    .line 411
    .line 412
    invoke-static {v11, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 413
    .line 414
    .line 415
    move-result v6

    .line 416
    goto/16 :goto_a

    .line 417
    .line 418
    :pswitch_11
    invoke-virtual {v0, v11, v1, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 419
    .line 420
    .line 421
    move-result v3

    .line 422
    if-eqz v3, :cond_9

    .line 423
    .line 424
    invoke-static {v11, v10, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 425
    .line 426
    .line 427
    move-result v6

    .line 428
    goto/16 :goto_a

    .line 429
    .line 430
    :pswitch_12
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v3

    .line 434
    invoke-virtual {v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->n(I)Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    move-result-object v9

    .line 438
    iget-object v10, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 439
    .line 440
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 441
    .line 442
    .line 443
    invoke-static {v3, v9}, Lcom/google/crypto/tink/shaded/protobuf/n0;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 444
    .line 445
    .line 446
    goto/16 :goto_a

    .line 447
    .line 448
    :pswitch_13
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    move-result-object v3

    .line 452
    check-cast v3, Ljava/util/List;

    .line 453
    .line 454
    invoke-virtual {v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 455
    .line 456
    .line 457
    move-result-object v9

    .line 458
    sget-object v10, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 459
    .line 460
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 461
    .line 462
    .line 463
    move-result v10

    .line 464
    if-nez v10, :cond_4

    .line 465
    .line 466
    const/4 v13, 0x0

    .line 467
    goto :goto_9

    .line 468
    :cond_4
    const/4 v12, 0x0

    .line 469
    const/4 v13, 0x0

    .line 470
    :goto_8
    if-ge v12, v10, :cond_5

    .line 471
    .line 472
    invoke-interface {v3, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 473
    .line 474
    .line 475
    move-result-object v14

    .line 476
    check-cast v14, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 477
    .line 478
    invoke-static {v11, v14, v9}, Lcom/google/crypto/tink/shaded/protobuf/k;->D(ILcom/google/crypto/tink/shaded/protobuf/a;Lcom/google/crypto/tink/shaded/protobuf/a1;)I

    .line 479
    .line 480
    .line 481
    move-result v14

    .line 482
    add-int/2addr v13, v14

    .line 483
    add-int/lit8 v12, v12, 0x1

    .line 484
    .line 485
    goto :goto_8

    .line 486
    :cond_5
    :goto_9
    add-int/2addr v6, v13

    .line 487
    goto/16 :goto_a

    .line 488
    .line 489
    :pswitch_14
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 490
    .line 491
    .line 492
    move-result-object v3

    .line 493
    check-cast v3, Ljava/util/List;

    .line 494
    .line 495
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->p(Ljava/util/List;)I

    .line 496
    .line 497
    .line 498
    move-result v3

    .line 499
    if-lez v3, :cond_9

    .line 500
    .line 501
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 502
    .line 503
    .line 504
    move-result v9

    .line 505
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 506
    .line 507
    .line 508
    move-result v6

    .line 509
    goto/16 :goto_a

    .line 510
    .line 511
    :pswitch_15
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 512
    .line 513
    .line 514
    move-result-object v3

    .line 515
    check-cast v3, Ljava/util/List;

    .line 516
    .line 517
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->n(Ljava/util/List;)I

    .line 518
    .line 519
    .line 520
    move-result v3

    .line 521
    if-lez v3, :cond_9

    .line 522
    .line 523
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 524
    .line 525
    .line 526
    move-result v9

    .line 527
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 528
    .line 529
    .line 530
    move-result v6

    .line 531
    goto/16 :goto_a

    .line 532
    .line 533
    :pswitch_16
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 534
    .line 535
    .line 536
    move-result-object v3

    .line 537
    check-cast v3, Ljava/util/List;

    .line 538
    .line 539
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->g(Ljava/util/List;)I

    .line 540
    .line 541
    .line 542
    move-result v3

    .line 543
    if-lez v3, :cond_9

    .line 544
    .line 545
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 546
    .line 547
    .line 548
    move-result v9

    .line 549
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 550
    .line 551
    .line 552
    move-result v6

    .line 553
    goto/16 :goto_a

    .line 554
    .line 555
    :pswitch_17
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 556
    .line 557
    .line 558
    move-result-object v3

    .line 559
    check-cast v3, Ljava/util/List;

    .line 560
    .line 561
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->e(Ljava/util/List;)I

    .line 562
    .line 563
    .line 564
    move-result v3

    .line 565
    if-lez v3, :cond_9

    .line 566
    .line 567
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 568
    .line 569
    .line 570
    move-result v9

    .line 571
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 572
    .line 573
    .line 574
    move-result v6

    .line 575
    goto/16 :goto_a

    .line 576
    .line 577
    :pswitch_18
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 578
    .line 579
    .line 580
    move-result-object v3

    .line 581
    check-cast v3, Ljava/util/List;

    .line 582
    .line 583
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->c(Ljava/util/List;)I

    .line 584
    .line 585
    .line 586
    move-result v3

    .line 587
    if-lez v3, :cond_9

    .line 588
    .line 589
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 590
    .line 591
    .line 592
    move-result v9

    .line 593
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 594
    .line 595
    .line 596
    move-result v6

    .line 597
    goto/16 :goto_a

    .line 598
    .line 599
    :pswitch_19
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 600
    .line 601
    .line 602
    move-result-object v3

    .line 603
    check-cast v3, Ljava/util/List;

    .line 604
    .line 605
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->s(Ljava/util/List;)I

    .line 606
    .line 607
    .line 608
    move-result v3

    .line 609
    if-lez v3, :cond_9

    .line 610
    .line 611
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 612
    .line 613
    .line 614
    move-result v9

    .line 615
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 616
    .line 617
    .line 618
    move-result v6

    .line 619
    goto/16 :goto_a

    .line 620
    .line 621
    :pswitch_1a
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 622
    .line 623
    .line 624
    move-result-object v3

    .line 625
    check-cast v3, Ljava/util/List;

    .line 626
    .line 627
    sget-object v9, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 628
    .line 629
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 630
    .line 631
    .line 632
    move-result v3

    .line 633
    if-lez v3, :cond_9

    .line 634
    .line 635
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 636
    .line 637
    .line 638
    move-result v9

    .line 639
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 640
    .line 641
    .line 642
    move-result v6

    .line 643
    goto/16 :goto_a

    .line 644
    .line 645
    :pswitch_1b
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 646
    .line 647
    .line 648
    move-result-object v3

    .line 649
    check-cast v3, Ljava/util/List;

    .line 650
    .line 651
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->e(Ljava/util/List;)I

    .line 652
    .line 653
    .line 654
    move-result v3

    .line 655
    if-lez v3, :cond_9

    .line 656
    .line 657
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 658
    .line 659
    .line 660
    move-result v9

    .line 661
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 662
    .line 663
    .line 664
    move-result v6

    .line 665
    goto/16 :goto_a

    .line 666
    .line 667
    :pswitch_1c
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 668
    .line 669
    .line 670
    move-result-object v3

    .line 671
    check-cast v3, Ljava/util/List;

    .line 672
    .line 673
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->g(Ljava/util/List;)I

    .line 674
    .line 675
    .line 676
    move-result v3

    .line 677
    if-lez v3, :cond_9

    .line 678
    .line 679
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 680
    .line 681
    .line 682
    move-result v9

    .line 683
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 684
    .line 685
    .line 686
    move-result v6

    .line 687
    goto/16 :goto_a

    .line 688
    .line 689
    :pswitch_1d
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 690
    .line 691
    .line 692
    move-result-object v3

    .line 693
    check-cast v3, Ljava/util/List;

    .line 694
    .line 695
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->i(Ljava/util/List;)I

    .line 696
    .line 697
    .line 698
    move-result v3

    .line 699
    if-lez v3, :cond_9

    .line 700
    .line 701
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 702
    .line 703
    .line 704
    move-result v9

    .line 705
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 706
    .line 707
    .line 708
    move-result v6

    .line 709
    goto/16 :goto_a

    .line 710
    .line 711
    :pswitch_1e
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 712
    .line 713
    .line 714
    move-result-object v3

    .line 715
    check-cast v3, Ljava/util/List;

    .line 716
    .line 717
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->u(Ljava/util/List;)I

    .line 718
    .line 719
    .line 720
    move-result v3

    .line 721
    if-lez v3, :cond_9

    .line 722
    .line 723
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 724
    .line 725
    .line 726
    move-result v9

    .line 727
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 728
    .line 729
    .line 730
    move-result v6

    .line 731
    goto/16 :goto_a

    .line 732
    .line 733
    :pswitch_1f
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 734
    .line 735
    .line 736
    move-result-object v3

    .line 737
    check-cast v3, Ljava/util/List;

    .line 738
    .line 739
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->k(Ljava/util/List;)I

    .line 740
    .line 741
    .line 742
    move-result v3

    .line 743
    if-lez v3, :cond_9

    .line 744
    .line 745
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 746
    .line 747
    .line 748
    move-result v9

    .line 749
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 750
    .line 751
    .line 752
    move-result v6

    .line 753
    goto/16 :goto_a

    .line 754
    .line 755
    :pswitch_20
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 756
    .line 757
    .line 758
    move-result-object v3

    .line 759
    check-cast v3, Ljava/util/List;

    .line 760
    .line 761
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->e(Ljava/util/List;)I

    .line 762
    .line 763
    .line 764
    move-result v3

    .line 765
    if-lez v3, :cond_9

    .line 766
    .line 767
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 768
    .line 769
    .line 770
    move-result v9

    .line 771
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 772
    .line 773
    .line 774
    move-result v6

    .line 775
    goto/16 :goto_a

    .line 776
    .line 777
    :pswitch_21
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 778
    .line 779
    .line 780
    move-result-object v3

    .line 781
    check-cast v3, Ljava/util/List;

    .line 782
    .line 783
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->g(Ljava/util/List;)I

    .line 784
    .line 785
    .line 786
    move-result v3

    .line 787
    if-lez v3, :cond_9

    .line 788
    .line 789
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 790
    .line 791
    .line 792
    move-result v9

    .line 793
    invoke-static {v3, v9, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 794
    .line 795
    .line 796
    move-result v6

    .line 797
    goto/16 :goto_a

    .line 798
    .line 799
    :pswitch_22
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 800
    .line 801
    .line 802
    move-result-object v3

    .line 803
    check-cast v3, Ljava/util/List;

    .line 804
    .line 805
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->o(ILjava/util/List;)I

    .line 806
    .line 807
    .line 808
    move-result v3

    .line 809
    goto/16 :goto_2

    .line 810
    .line 811
    :pswitch_23
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 812
    .line 813
    .line 814
    move-result-object v3

    .line 815
    check-cast v3, Ljava/util/List;

    .line 816
    .line 817
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->m(ILjava/util/List;)I

    .line 818
    .line 819
    .line 820
    move-result v3

    .line 821
    goto/16 :goto_2

    .line 822
    .line 823
    :pswitch_24
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 824
    .line 825
    .line 826
    move-result-object v3

    .line 827
    check-cast v3, Ljava/util/List;

    .line 828
    .line 829
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->f(ILjava/util/List;)I

    .line 830
    .line 831
    .line 832
    move-result v3

    .line 833
    goto/16 :goto_2

    .line 834
    .line 835
    :pswitch_25
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 836
    .line 837
    .line 838
    move-result-object v3

    .line 839
    check-cast v3, Ljava/util/List;

    .line 840
    .line 841
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->d(ILjava/util/List;)I

    .line 842
    .line 843
    .line 844
    move-result v3

    .line 845
    goto/16 :goto_2

    .line 846
    .line 847
    :pswitch_26
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 848
    .line 849
    .line 850
    move-result-object v3

    .line 851
    check-cast v3, Ljava/util/List;

    .line 852
    .line 853
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->b(ILjava/util/List;)I

    .line 854
    .line 855
    .line 856
    move-result v3

    .line 857
    goto/16 :goto_2

    .line 858
    .line 859
    :pswitch_27
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 860
    .line 861
    .line 862
    move-result-object v3

    .line 863
    check-cast v3, Ljava/util/List;

    .line 864
    .line 865
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->r(ILjava/util/List;)I

    .line 866
    .line 867
    .line 868
    move-result v3

    .line 869
    goto/16 :goto_2

    .line 870
    .line 871
    :pswitch_28
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 872
    .line 873
    .line 874
    move-result-object v3

    .line 875
    check-cast v3, Ljava/util/List;

    .line 876
    .line 877
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->a(ILjava/util/List;)I

    .line 878
    .line 879
    .line 880
    move-result v3

    .line 881
    goto/16 :goto_2

    .line 882
    .line 883
    :pswitch_29
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 884
    .line 885
    .line 886
    move-result-object v3

    .line 887
    check-cast v3, Ljava/util/List;

    .line 888
    .line 889
    invoke-virtual {v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 890
    .line 891
    .line 892
    move-result-object v9

    .line 893
    invoke-static {v11, v3, v9}, Lcom/google/crypto/tink/shaded/protobuf/b1;->l(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/a1;)I

    .line 894
    .line 895
    .line 896
    move-result v3

    .line 897
    goto/16 :goto_2

    .line 898
    .line 899
    :pswitch_2a
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 900
    .line 901
    .line 902
    move-result-object v3

    .line 903
    check-cast v3, Ljava/util/List;

    .line 904
    .line 905
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->q(ILjava/util/List;)I

    .line 906
    .line 907
    .line 908
    move-result v3

    .line 909
    goto/16 :goto_2

    .line 910
    .line 911
    :pswitch_2b
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 912
    .line 913
    .line 914
    move-result-object v3

    .line 915
    check-cast v3, Ljava/util/List;

    .line 916
    .line 917
    sget-object v9, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 918
    .line 919
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 920
    .line 921
    .line 922
    move-result v3

    .line 923
    if-nez v3, :cond_6

    .line 924
    .line 925
    const/4 v9, 0x0

    .line 926
    goto/16 :goto_4

    .line 927
    .line 928
    :cond_6
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 929
    .line 930
    .line 931
    move-result v9

    .line 932
    add-int/2addr v9, v15

    .line 933
    mul-int/2addr v9, v3

    .line 934
    goto/16 :goto_4

    .line 935
    .line 936
    :pswitch_2c
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 937
    .line 938
    .line 939
    move-result-object v3

    .line 940
    check-cast v3, Ljava/util/List;

    .line 941
    .line 942
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->d(ILjava/util/List;)I

    .line 943
    .line 944
    .line 945
    move-result v3

    .line 946
    goto/16 :goto_2

    .line 947
    .line 948
    :pswitch_2d
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 949
    .line 950
    .line 951
    move-result-object v3

    .line 952
    check-cast v3, Ljava/util/List;

    .line 953
    .line 954
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->f(ILjava/util/List;)I

    .line 955
    .line 956
    .line 957
    move-result v3

    .line 958
    goto/16 :goto_2

    .line 959
    .line 960
    :pswitch_2e
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 961
    .line 962
    .line 963
    move-result-object v3

    .line 964
    check-cast v3, Ljava/util/List;

    .line 965
    .line 966
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->h(ILjava/util/List;)I

    .line 967
    .line 968
    .line 969
    move-result v3

    .line 970
    goto/16 :goto_2

    .line 971
    .line 972
    :pswitch_2f
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 973
    .line 974
    .line 975
    move-result-object v3

    .line 976
    check-cast v3, Ljava/util/List;

    .line 977
    .line 978
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->t(ILjava/util/List;)I

    .line 979
    .line 980
    .line 981
    move-result v3

    .line 982
    goto/16 :goto_2

    .line 983
    .line 984
    :pswitch_30
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 985
    .line 986
    .line 987
    move-result-object v3

    .line 988
    check-cast v3, Ljava/util/List;

    .line 989
    .line 990
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->j(ILjava/util/List;)I

    .line 991
    .line 992
    .line 993
    move-result v3

    .line 994
    goto/16 :goto_2

    .line 995
    .line 996
    :pswitch_31
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 997
    .line 998
    .line 999
    move-result-object v3

    .line 1000
    check-cast v3, Ljava/util/List;

    .line 1001
    .line 1002
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->d(ILjava/util/List;)I

    .line 1003
    .line 1004
    .line 1005
    move-result v3

    .line 1006
    goto/16 :goto_2

    .line 1007
    .line 1008
    :pswitch_32
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1009
    .line 1010
    .line 1011
    move-result-object v3

    .line 1012
    check-cast v3, Ljava/util/List;

    .line 1013
    .line 1014
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/b1;->f(ILjava/util/List;)I

    .line 1015
    .line 1016
    .line 1017
    move-result v3

    .line 1018
    goto/16 :goto_2

    .line 1019
    .line 1020
    :pswitch_33
    and-int v3, v8, v9

    .line 1021
    .line 1022
    if-eqz v3, :cond_9

    .line 1023
    .line 1024
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v3

    .line 1028
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 1029
    .line 1030
    invoke-virtual {v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1031
    .line 1032
    .line 1033
    move-result-object v9

    .line 1034
    invoke-static {v11, v3, v9}, Lcom/google/crypto/tink/shaded/protobuf/k;->D(ILcom/google/crypto/tink/shaded/protobuf/a;Lcom/google/crypto/tink/shaded/protobuf/a1;)I

    .line 1035
    .line 1036
    .line 1037
    move-result v3

    .line 1038
    goto/16 :goto_2

    .line 1039
    .line 1040
    :pswitch_34
    and-int v3, v8, v9

    .line 1041
    .line 1042
    if-eqz v3, :cond_9

    .line 1043
    .line 1044
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1045
    .line 1046
    .line 1047
    move-result-wide v9

    .line 1048
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1049
    .line 1050
    .line 1051
    move-result v3

    .line 1052
    shl-long v11, v9, v15

    .line 1053
    .line 1054
    shr-long v9, v9, v16

    .line 1055
    .line 1056
    xor-long/2addr v9, v11

    .line 1057
    invoke-static {v9, v10}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 1058
    .line 1059
    .line 1060
    move-result v9

    .line 1061
    goto/16 :goto_3

    .line 1062
    .line 1063
    :pswitch_35
    and-int v3, v8, v9

    .line 1064
    .line 1065
    if-eqz v3, :cond_9

    .line 1066
    .line 1067
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1068
    .line 1069
    .line 1070
    move-result v3

    .line 1071
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1072
    .line 1073
    .line 1074
    move-result v9

    .line 1075
    shl-int/lit8 v10, v3, 0x1

    .line 1076
    .line 1077
    shr-int/lit8 v3, v3, 0x1f

    .line 1078
    .line 1079
    xor-int/2addr v3, v10

    .line 1080
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 1081
    .line 1082
    .line 1083
    move-result v3

    .line 1084
    goto/16 :goto_5

    .line 1085
    .line 1086
    :pswitch_36
    and-int v3, v8, v9

    .line 1087
    .line 1088
    if-eqz v3, :cond_9

    .line 1089
    .line 1090
    invoke-static {v11, v10, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1091
    .line 1092
    .line 1093
    move-result v6

    .line 1094
    goto/16 :goto_a

    .line 1095
    .line 1096
    :pswitch_37
    and-int/2addr v9, v8

    .line 1097
    if-eqz v9, :cond_9

    .line 1098
    .line 1099
    invoke-static {v11, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1100
    .line 1101
    .line 1102
    move-result v6

    .line 1103
    goto/16 :goto_a

    .line 1104
    .line 1105
    :pswitch_38
    and-int v3, v8, v9

    .line 1106
    .line 1107
    if-eqz v3, :cond_9

    .line 1108
    .line 1109
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1110
    .line 1111
    .line 1112
    move-result v3

    .line 1113
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1114
    .line 1115
    .line 1116
    move-result v9

    .line 1117
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->E(I)I

    .line 1118
    .line 1119
    .line 1120
    move-result v3

    .line 1121
    goto/16 :goto_5

    .line 1122
    .line 1123
    :pswitch_39
    and-int v3, v8, v9

    .line 1124
    .line 1125
    if-eqz v3, :cond_9

    .line 1126
    .line 1127
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1128
    .line 1129
    .line 1130
    move-result v3

    .line 1131
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1132
    .line 1133
    .line 1134
    move-result v9

    .line 1135
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 1136
    .line 1137
    .line 1138
    move-result v3

    .line 1139
    goto/16 :goto_5

    .line 1140
    .line 1141
    :pswitch_3a
    and-int v3, v8, v9

    .line 1142
    .line 1143
    if-eqz v3, :cond_9

    .line 1144
    .line 1145
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1146
    .line 1147
    .line 1148
    move-result-object v3

    .line 1149
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 1150
    .line 1151
    invoke-static {v11, v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->z(ILcom/google/crypto/tink/shaded/protobuf/i;)I

    .line 1152
    .line 1153
    .line 1154
    move-result v3

    .line 1155
    goto/16 :goto_2

    .line 1156
    .line 1157
    :pswitch_3b
    and-int v3, v8, v9

    .line 1158
    .line 1159
    if-eqz v3, :cond_9

    .line 1160
    .line 1161
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1162
    .line 1163
    .line 1164
    move-result-object v3

    .line 1165
    invoke-virtual {v0, v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1166
    .line 1167
    .line 1168
    move-result-object v9

    .line 1169
    sget-object v10, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 1170
    .line 1171
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 1172
    .line 1173
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1174
    .line 1175
    .line 1176
    move-result v10

    .line 1177
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1178
    .line 1179
    .line 1180
    move-object v11, v3

    .line 1181
    check-cast v11, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1182
    .line 1183
    iget v12, v11, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 1184
    .line 1185
    if-ne v12, v4, :cond_7

    .line 1186
    .line 1187
    invoke-interface {v9, v3}, Lcom/google/crypto/tink/shaded/protobuf/a1;->i(Lcom/google/crypto/tink/shaded/protobuf/a;)I

    .line 1188
    .line 1189
    .line 1190
    move-result v12

    .line 1191
    iput v12, v11, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 1192
    .line 1193
    :cond_7
    invoke-static {v12, v12, v10, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 1194
    .line 1195
    .line 1196
    move-result v6

    .line 1197
    goto/16 :goto_a

    .line 1198
    .line 1199
    :pswitch_3c
    and-int v3, v8, v9

    .line 1200
    .line 1201
    if-eqz v3, :cond_9

    .line 1202
    .line 1203
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1204
    .line 1205
    .line 1206
    move-result-object v3

    .line 1207
    instance-of v9, v3, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 1208
    .line 1209
    if-eqz v9, :cond_8

    .line 1210
    .line 1211
    check-cast v3, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 1212
    .line 1213
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1214
    .line 1215
    .line 1216
    move-result v9

    .line 1217
    invoke-virtual {v3}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 1218
    .line 1219
    .line 1220
    move-result v3

    .line 1221
    invoke-static {v3, v3, v9, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 1222
    .line 1223
    .line 1224
    move-result v3

    .line 1225
    goto/16 :goto_6

    .line 1226
    .line 1227
    :cond_8
    check-cast v3, Ljava/lang/String;

    .line 1228
    .line 1229
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1230
    .line 1231
    .line 1232
    move-result v9

    .line 1233
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->F(Ljava/lang/String;)I

    .line 1234
    .line 1235
    .line 1236
    move-result v3

    .line 1237
    goto/16 :goto_7

    .line 1238
    .line 1239
    :pswitch_3d
    and-int v3, v8, v9

    .line 1240
    .line 1241
    if-eqz v3, :cond_9

    .line 1242
    .line 1243
    invoke-static {v11, v15, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1244
    .line 1245
    .line 1246
    move-result v6

    .line 1247
    goto :goto_a

    .line 1248
    :pswitch_3e
    and-int v3, v8, v9

    .line 1249
    .line 1250
    if-eqz v3, :cond_9

    .line 1251
    .line 1252
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->B(I)I

    .line 1253
    .line 1254
    .line 1255
    move-result v3

    .line 1256
    goto/16 :goto_2

    .line 1257
    .line 1258
    :pswitch_3f
    and-int v3, v8, v9

    .line 1259
    .line 1260
    if-eqz v3, :cond_9

    .line 1261
    .line 1262
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->C(I)I

    .line 1263
    .line 1264
    .line 1265
    move-result v3

    .line 1266
    goto/16 :goto_2

    .line 1267
    .line 1268
    :pswitch_40
    and-int v3, v8, v9

    .line 1269
    .line 1270
    if-eqz v3, :cond_9

    .line 1271
    .line 1272
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getInt(Ljava/lang/Object;J)I

    .line 1273
    .line 1274
    .line 1275
    move-result v3

    .line 1276
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1277
    .line 1278
    .line 1279
    move-result v9

    .line 1280
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/k;->E(I)I

    .line 1281
    .line 1282
    .line 1283
    move-result v3

    .line 1284
    goto/16 :goto_5

    .line 1285
    .line 1286
    :pswitch_41
    and-int v3, v8, v9

    .line 1287
    .line 1288
    if-eqz v3, :cond_9

    .line 1289
    .line 1290
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1291
    .line 1292
    .line 1293
    move-result-wide v9

    .line 1294
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1295
    .line 1296
    .line 1297
    move-result v3

    .line 1298
    invoke-static {v9, v10}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 1299
    .line 1300
    .line 1301
    move-result v9

    .line 1302
    goto/16 :goto_3

    .line 1303
    .line 1304
    :pswitch_42
    and-int v3, v8, v9

    .line 1305
    .line 1306
    if-eqz v3, :cond_9

    .line 1307
    .line 1308
    invoke-virtual {v2, v1, v13, v14}, Lsun/misc/Unsafe;->getLong(Ljava/lang/Object;J)J

    .line 1309
    .line 1310
    .line 1311
    move-result-wide v9

    .line 1312
    invoke-static {v11}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1313
    .line 1314
    .line 1315
    move-result v3

    .line 1316
    invoke-static {v9, v10}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 1317
    .line 1318
    .line 1319
    move-result v9

    .line 1320
    goto/16 :goto_3

    .line 1321
    .line 1322
    :pswitch_43
    and-int/2addr v9, v8

    .line 1323
    if-eqz v9, :cond_9

    .line 1324
    .line 1325
    invoke-static {v11, v3, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1326
    .line 1327
    .line 1328
    move-result v6

    .line 1329
    goto :goto_a

    .line 1330
    :pswitch_44
    and-int v3, v8, v9

    .line 1331
    .line 1332
    if-eqz v3, :cond_9

    .line 1333
    .line 1334
    invoke-static {v11, v10, v6}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1335
    .line 1336
    .line 1337
    move-result v6

    .line 1338
    :cond_9
    :goto_a
    add-int/lit8 v5, v5, 0x3

    .line 1339
    .line 1340
    goto/16 :goto_0

    .line 1341
    .line 1342
    :cond_a
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 1343
    .line 1344
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1345
    .line 1346
    .line 1347
    move-object v0, v1

    .line 1348
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1349
    .line 1350
    iget-object v0, v0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 1351
    .line 1352
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/c1;->a()I

    .line 1353
    .line 1354
    .line 1355
    move-result v0

    .line 1356
    add-int/2addr v0, v6

    .line 1357
    return v0

    .line 1358
    nop

    .line 1359
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final q(Ljava/lang/Object;)I
    .locals 13

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/r0;->p:Lsun/misc/Unsafe;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    move v2, v1

    .line 5
    move v3, v2

    .line 6
    :goto_0
    iget-object v4, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 7
    .line 8
    array-length v5, v4

    .line 9
    if-ge v2, v5, :cond_9

    .line 10
    .line 11
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 12
    .line 13
    .line 14
    move-result v5

    .line 15
    invoke-static {v5}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 16
    .line 17
    .line 18
    move-result v6

    .line 19
    aget v7, v4, v2

    .line 20
    .line 21
    const v8, 0xfffff

    .line 22
    .line 23
    .line 24
    and-int/2addr v5, v8

    .line 25
    int-to-long v8, v5

    .line 26
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/s;->e:Lcom/google/crypto/tink/shaded/protobuf/s;

    .line 27
    .line 28
    iget v5, v5, Lcom/google/crypto/tink/shaded/protobuf/s;->d:I

    .line 29
    .line 30
    if-lt v6, v5, :cond_0

    .line 31
    .line 32
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/s;->f:Lcom/google/crypto/tink/shaded/protobuf/s;

    .line 33
    .line 34
    iget v5, v5, Lcom/google/crypto/tink/shaded/protobuf/s;->d:I

    .line 35
    .line 36
    if-gt v6, v5, :cond_0

    .line 37
    .line 38
    add-int/lit8 v5, v2, 0x2

    .line 39
    .line 40
    aget v4, v4, v5

    .line 41
    .line 42
    :cond_0
    const/4 v4, -0x1

    .line 43
    const/16 v5, 0x3f

    .line 44
    .line 45
    const/4 v10, 0x4

    .line 46
    const/16 v11, 0x8

    .line 47
    .line 48
    const/4 v12, 0x1

    .line 49
    packed-switch v6, :pswitch_data_0

    .line 50
    .line 51
    .line 52
    goto/16 :goto_9

    .line 53
    .line 54
    :pswitch_0
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-eqz v4, :cond_8

    .line 59
    .line 60
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 61
    .line 62
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 67
    .line 68
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    invoke-static {v7, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/k;->D(ILcom/google/crypto/tink/shaded/protobuf/a;Lcom/google/crypto/tink/shaded/protobuf/a1;)I

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    :goto_1
    add-int/2addr v3, v4

    .line 77
    goto/16 :goto_9

    .line 78
    .line 79
    :pswitch_1
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    if-eqz v4, :cond_8

    .line 84
    .line 85
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 86
    .line 87
    .line 88
    move-result-wide v8

    .line 89
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    shl-long v6, v8, v12

    .line 94
    .line 95
    shr-long/2addr v8, v5

    .line 96
    xor-long v5, v6, v8

    .line 97
    .line 98
    invoke-static {v5, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    :goto_2
    add-int/2addr v5, v4

    .line 103
    :goto_3
    add-int/2addr v3, v5

    .line 104
    goto/16 :goto_9

    .line 105
    .line 106
    :pswitch_2
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 107
    .line 108
    .line 109
    move-result v4

    .line 110
    if-eqz v4, :cond_8

    .line 111
    .line 112
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 113
    .line 114
    .line 115
    move-result v4

    .line 116
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 117
    .line 118
    .line 119
    move-result v5

    .line 120
    shl-int/lit8 v6, v4, 0x1

    .line 121
    .line 122
    shr-int/lit8 v4, v4, 0x1f

    .line 123
    .line 124
    xor-int/2addr v4, v6

    .line 125
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 126
    .line 127
    .line 128
    move-result v4

    .line 129
    :goto_4
    add-int/2addr v4, v5

    .line 130
    goto :goto_1

    .line 131
    :pswitch_3
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 132
    .line 133
    .line 134
    move-result v4

    .line 135
    if-eqz v4, :cond_8

    .line 136
    .line 137
    invoke-static {v7, v11, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 138
    .line 139
    .line 140
    move-result v3

    .line 141
    goto/16 :goto_9

    .line 142
    .line 143
    :pswitch_4
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 144
    .line 145
    .line 146
    move-result v4

    .line 147
    if-eqz v4, :cond_8

    .line 148
    .line 149
    invoke-static {v7, v10, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 150
    .line 151
    .line 152
    move-result v3

    .line 153
    goto/16 :goto_9

    .line 154
    .line 155
    :pswitch_5
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 156
    .line 157
    .line 158
    move-result v4

    .line 159
    if-eqz v4, :cond_8

    .line 160
    .line 161
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 166
    .line 167
    .line 168
    move-result v5

    .line 169
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->E(I)I

    .line 170
    .line 171
    .line 172
    move-result v4

    .line 173
    goto :goto_4

    .line 174
    :pswitch_6
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 175
    .line 176
    .line 177
    move-result v4

    .line 178
    if-eqz v4, :cond_8

    .line 179
    .line 180
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 185
    .line 186
    .line 187
    move-result v5

    .line 188
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 189
    .line 190
    .line 191
    move-result v4

    .line 192
    goto :goto_4

    .line 193
    :pswitch_7
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 194
    .line 195
    .line 196
    move-result v4

    .line 197
    if-eqz v4, :cond_8

    .line 198
    .line 199
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 200
    .line 201
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v4

    .line 205
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 206
    .line 207
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->z(ILcom/google/crypto/tink/shaded/protobuf/i;)I

    .line 208
    .line 209
    .line 210
    move-result v4

    .line 211
    goto/16 :goto_1

    .line 212
    .line 213
    :pswitch_8
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 214
    .line 215
    .line 216
    move-result v5

    .line 217
    if-eqz v5, :cond_8

    .line 218
    .line 219
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 220
    .line 221
    invoke-virtual {v5, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 226
    .line 227
    .line 228
    move-result-object v6

    .line 229
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 230
    .line 231
    check-cast v5, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 232
    .line 233
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 234
    .line 235
    .line 236
    move-result v7

    .line 237
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 238
    .line 239
    .line 240
    move-object v8, v5

    .line 241
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 242
    .line 243
    iget v9, v8, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 244
    .line 245
    if-ne v9, v4, :cond_1

    .line 246
    .line 247
    invoke-interface {v6, v5}, Lcom/google/crypto/tink/shaded/protobuf/a1;->i(Lcom/google/crypto/tink/shaded/protobuf/a;)I

    .line 248
    .line 249
    .line 250
    move-result v9

    .line 251
    iput v9, v8, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 252
    .line 253
    :cond_1
    invoke-static {v9, v9, v7, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 254
    .line 255
    .line 256
    move-result v3

    .line 257
    goto/16 :goto_9

    .line 258
    .line 259
    :pswitch_9
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 260
    .line 261
    .line 262
    move-result v4

    .line 263
    if-eqz v4, :cond_8

    .line 264
    .line 265
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 266
    .line 267
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v4

    .line 271
    instance-of v5, v4, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 272
    .line 273
    if-eqz v5, :cond_2

    .line 274
    .line 275
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 276
    .line 277
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 278
    .line 279
    .line 280
    move-result v5

    .line 281
    invoke-virtual {v4}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 282
    .line 283
    .line 284
    move-result v4

    .line 285
    invoke-static {v4, v4, v5, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 286
    .line 287
    .line 288
    move-result v3

    .line 289
    goto/16 :goto_9

    .line 290
    .line 291
    :cond_2
    check-cast v4, Ljava/lang/String;

    .line 292
    .line 293
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 294
    .line 295
    .line 296
    move-result v5

    .line 297
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->F(Ljava/lang/String;)I

    .line 298
    .line 299
    .line 300
    move-result v4

    .line 301
    :goto_5
    add-int/2addr v4, v5

    .line 302
    add-int/2addr v4, v3

    .line 303
    move v3, v4

    .line 304
    goto/16 :goto_9

    .line 305
    .line 306
    :pswitch_a
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 307
    .line 308
    .line 309
    move-result v4

    .line 310
    if-eqz v4, :cond_8

    .line 311
    .line 312
    invoke-static {v7, v12, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 313
    .line 314
    .line 315
    move-result v3

    .line 316
    goto/16 :goto_9

    .line 317
    .line 318
    :pswitch_b
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 319
    .line 320
    .line 321
    move-result v4

    .line 322
    if-eqz v4, :cond_8

    .line 323
    .line 324
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->B(I)I

    .line 325
    .line 326
    .line 327
    move-result v4

    .line 328
    goto/16 :goto_1

    .line 329
    .line 330
    :pswitch_c
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 331
    .line 332
    .line 333
    move-result v4

    .line 334
    if-eqz v4, :cond_8

    .line 335
    .line 336
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->C(I)I

    .line 337
    .line 338
    .line 339
    move-result v4

    .line 340
    goto/16 :goto_1

    .line 341
    .line 342
    :pswitch_d
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 343
    .line 344
    .line 345
    move-result v4

    .line 346
    if-eqz v4, :cond_8

    .line 347
    .line 348
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->A(JLjava/lang/Object;)I

    .line 349
    .line 350
    .line 351
    move-result v4

    .line 352
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 353
    .line 354
    .line 355
    move-result v5

    .line 356
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->E(I)I

    .line 357
    .line 358
    .line 359
    move-result v4

    .line 360
    goto/16 :goto_4

    .line 361
    .line 362
    :pswitch_e
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 363
    .line 364
    .line 365
    move-result v4

    .line 366
    if-eqz v4, :cond_8

    .line 367
    .line 368
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 369
    .line 370
    .line 371
    move-result-wide v4

    .line 372
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 373
    .line 374
    .line 375
    move-result v6

    .line 376
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 377
    .line 378
    .line 379
    move-result v4

    .line 380
    :goto_6
    add-int/2addr v4, v6

    .line 381
    goto/16 :goto_1

    .line 382
    .line 383
    :pswitch_f
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 384
    .line 385
    .line 386
    move-result v4

    .line 387
    if-eqz v4, :cond_8

    .line 388
    .line 389
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->B(JLjava/lang/Object;)J

    .line 390
    .line 391
    .line 392
    move-result-wide v4

    .line 393
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 394
    .line 395
    .line 396
    move-result v6

    .line 397
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 398
    .line 399
    .line 400
    move-result v4

    .line 401
    goto :goto_6

    .line 402
    :pswitch_10
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 403
    .line 404
    .line 405
    move-result v4

    .line 406
    if-eqz v4, :cond_8

    .line 407
    .line 408
    invoke-static {v7, v10, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 409
    .line 410
    .line 411
    move-result v3

    .line 412
    goto/16 :goto_9

    .line 413
    .line 414
    :pswitch_11
    invoke-virtual {p0, v7, p1, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 415
    .line 416
    .line 417
    move-result v4

    .line 418
    if-eqz v4, :cond_8

    .line 419
    .line 420
    invoke-static {v7, v11, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 421
    .line 422
    .line 423
    move-result v3

    .line 424
    goto/16 :goto_9

    .line 425
    .line 426
    :pswitch_12
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 427
    .line 428
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v4

    .line 432
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->n(I)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v5

    .line 436
    iget-object v6, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 437
    .line 438
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 439
    .line 440
    .line 441
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/n0;->a(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 442
    .line 443
    .line 444
    goto/16 :goto_9

    .line 445
    .line 446
    :pswitch_13
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 447
    .line 448
    .line 449
    move-result-object v4

    .line 450
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 451
    .line 452
    .line 453
    move-result-object v5

    .line 454
    sget-object v6, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 455
    .line 456
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 457
    .line 458
    .line 459
    move-result v6

    .line 460
    if-nez v6, :cond_3

    .line 461
    .line 462
    move v9, v1

    .line 463
    goto :goto_8

    .line 464
    :cond_3
    move v8, v1

    .line 465
    move v9, v8

    .line 466
    :goto_7
    if-ge v8, v6, :cond_4

    .line 467
    .line 468
    invoke-interface {v4, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    move-result-object v10

    .line 472
    check-cast v10, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 473
    .line 474
    invoke-static {v7, v10, v5}, Lcom/google/crypto/tink/shaded/protobuf/k;->D(ILcom/google/crypto/tink/shaded/protobuf/a;Lcom/google/crypto/tink/shaded/protobuf/a1;)I

    .line 475
    .line 476
    .line 477
    move-result v10

    .line 478
    add-int/2addr v9, v10

    .line 479
    add-int/lit8 v8, v8, 0x1

    .line 480
    .line 481
    goto :goto_7

    .line 482
    :cond_4
    :goto_8
    add-int/2addr v3, v9

    .line 483
    goto/16 :goto_9

    .line 484
    .line 485
    :pswitch_14
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object v4

    .line 489
    check-cast v4, Ljava/util/List;

    .line 490
    .line 491
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->p(Ljava/util/List;)I

    .line 492
    .line 493
    .line 494
    move-result v4

    .line 495
    if-lez v4, :cond_8

    .line 496
    .line 497
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 498
    .line 499
    .line 500
    move-result v5

    .line 501
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 502
    .line 503
    .line 504
    move-result v3

    .line 505
    goto/16 :goto_9

    .line 506
    .line 507
    :pswitch_15
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 508
    .line 509
    .line 510
    move-result-object v4

    .line 511
    check-cast v4, Ljava/util/List;

    .line 512
    .line 513
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->n(Ljava/util/List;)I

    .line 514
    .line 515
    .line 516
    move-result v4

    .line 517
    if-lez v4, :cond_8

    .line 518
    .line 519
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 520
    .line 521
    .line 522
    move-result v5

    .line 523
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 524
    .line 525
    .line 526
    move-result v3

    .line 527
    goto/16 :goto_9

    .line 528
    .line 529
    :pswitch_16
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 530
    .line 531
    .line 532
    move-result-object v4

    .line 533
    check-cast v4, Ljava/util/List;

    .line 534
    .line 535
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->g(Ljava/util/List;)I

    .line 536
    .line 537
    .line 538
    move-result v4

    .line 539
    if-lez v4, :cond_8

    .line 540
    .line 541
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 542
    .line 543
    .line 544
    move-result v5

    .line 545
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 546
    .line 547
    .line 548
    move-result v3

    .line 549
    goto/16 :goto_9

    .line 550
    .line 551
    :pswitch_17
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 552
    .line 553
    .line 554
    move-result-object v4

    .line 555
    check-cast v4, Ljava/util/List;

    .line 556
    .line 557
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->e(Ljava/util/List;)I

    .line 558
    .line 559
    .line 560
    move-result v4

    .line 561
    if-lez v4, :cond_8

    .line 562
    .line 563
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 564
    .line 565
    .line 566
    move-result v5

    .line 567
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 568
    .line 569
    .line 570
    move-result v3

    .line 571
    goto/16 :goto_9

    .line 572
    .line 573
    :pswitch_18
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 574
    .line 575
    .line 576
    move-result-object v4

    .line 577
    check-cast v4, Ljava/util/List;

    .line 578
    .line 579
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->c(Ljava/util/List;)I

    .line 580
    .line 581
    .line 582
    move-result v4

    .line 583
    if-lez v4, :cond_8

    .line 584
    .line 585
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 586
    .line 587
    .line 588
    move-result v5

    .line 589
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 590
    .line 591
    .line 592
    move-result v3

    .line 593
    goto/16 :goto_9

    .line 594
    .line 595
    :pswitch_19
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 596
    .line 597
    .line 598
    move-result-object v4

    .line 599
    check-cast v4, Ljava/util/List;

    .line 600
    .line 601
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->s(Ljava/util/List;)I

    .line 602
    .line 603
    .line 604
    move-result v4

    .line 605
    if-lez v4, :cond_8

    .line 606
    .line 607
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 608
    .line 609
    .line 610
    move-result v5

    .line 611
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 612
    .line 613
    .line 614
    move-result v3

    .line 615
    goto/16 :goto_9

    .line 616
    .line 617
    :pswitch_1a
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 618
    .line 619
    .line 620
    move-result-object v4

    .line 621
    check-cast v4, Ljava/util/List;

    .line 622
    .line 623
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 624
    .line 625
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 626
    .line 627
    .line 628
    move-result v4

    .line 629
    if-lez v4, :cond_8

    .line 630
    .line 631
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 632
    .line 633
    .line 634
    move-result v5

    .line 635
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 636
    .line 637
    .line 638
    move-result v3

    .line 639
    goto/16 :goto_9

    .line 640
    .line 641
    :pswitch_1b
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 642
    .line 643
    .line 644
    move-result-object v4

    .line 645
    check-cast v4, Ljava/util/List;

    .line 646
    .line 647
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->e(Ljava/util/List;)I

    .line 648
    .line 649
    .line 650
    move-result v4

    .line 651
    if-lez v4, :cond_8

    .line 652
    .line 653
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 654
    .line 655
    .line 656
    move-result v5

    .line 657
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 658
    .line 659
    .line 660
    move-result v3

    .line 661
    goto/16 :goto_9

    .line 662
    .line 663
    :pswitch_1c
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 664
    .line 665
    .line 666
    move-result-object v4

    .line 667
    check-cast v4, Ljava/util/List;

    .line 668
    .line 669
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->g(Ljava/util/List;)I

    .line 670
    .line 671
    .line 672
    move-result v4

    .line 673
    if-lez v4, :cond_8

    .line 674
    .line 675
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 676
    .line 677
    .line 678
    move-result v5

    .line 679
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 680
    .line 681
    .line 682
    move-result v3

    .line 683
    goto/16 :goto_9

    .line 684
    .line 685
    :pswitch_1d
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 686
    .line 687
    .line 688
    move-result-object v4

    .line 689
    check-cast v4, Ljava/util/List;

    .line 690
    .line 691
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->i(Ljava/util/List;)I

    .line 692
    .line 693
    .line 694
    move-result v4

    .line 695
    if-lez v4, :cond_8

    .line 696
    .line 697
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 698
    .line 699
    .line 700
    move-result v5

    .line 701
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 702
    .line 703
    .line 704
    move-result v3

    .line 705
    goto/16 :goto_9

    .line 706
    .line 707
    :pswitch_1e
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    move-result-object v4

    .line 711
    check-cast v4, Ljava/util/List;

    .line 712
    .line 713
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->u(Ljava/util/List;)I

    .line 714
    .line 715
    .line 716
    move-result v4

    .line 717
    if-lez v4, :cond_8

    .line 718
    .line 719
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 720
    .line 721
    .line 722
    move-result v5

    .line 723
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 724
    .line 725
    .line 726
    move-result v3

    .line 727
    goto/16 :goto_9

    .line 728
    .line 729
    :pswitch_1f
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 730
    .line 731
    .line 732
    move-result-object v4

    .line 733
    check-cast v4, Ljava/util/List;

    .line 734
    .line 735
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->k(Ljava/util/List;)I

    .line 736
    .line 737
    .line 738
    move-result v4

    .line 739
    if-lez v4, :cond_8

    .line 740
    .line 741
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 742
    .line 743
    .line 744
    move-result v5

    .line 745
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 746
    .line 747
    .line 748
    move-result v3

    .line 749
    goto/16 :goto_9

    .line 750
    .line 751
    :pswitch_20
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 752
    .line 753
    .line 754
    move-result-object v4

    .line 755
    check-cast v4, Ljava/util/List;

    .line 756
    .line 757
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->e(Ljava/util/List;)I

    .line 758
    .line 759
    .line 760
    move-result v4

    .line 761
    if-lez v4, :cond_8

    .line 762
    .line 763
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 764
    .line 765
    .line 766
    move-result v5

    .line 767
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 768
    .line 769
    .line 770
    move-result v3

    .line 771
    goto/16 :goto_9

    .line 772
    .line 773
    :pswitch_21
    invoke-virtual {v0, p1, v8, v9}, Lsun/misc/Unsafe;->getObject(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 774
    .line 775
    .line 776
    move-result-object v4

    .line 777
    check-cast v4, Ljava/util/List;

    .line 778
    .line 779
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->g(Ljava/util/List;)I

    .line 780
    .line 781
    .line 782
    move-result v4

    .line 783
    if-lez v4, :cond_8

    .line 784
    .line 785
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 786
    .line 787
    .line 788
    move-result v5

    .line 789
    invoke-static {v4, v5, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 790
    .line 791
    .line 792
    move-result v3

    .line 793
    goto/16 :goto_9

    .line 794
    .line 795
    :pswitch_22
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 796
    .line 797
    .line 798
    move-result-object v4

    .line 799
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->o(ILjava/util/List;)I

    .line 800
    .line 801
    .line 802
    move-result v4

    .line 803
    goto/16 :goto_1

    .line 804
    .line 805
    :pswitch_23
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 806
    .line 807
    .line 808
    move-result-object v4

    .line 809
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->m(ILjava/util/List;)I

    .line 810
    .line 811
    .line 812
    move-result v4

    .line 813
    goto/16 :goto_1

    .line 814
    .line 815
    :pswitch_24
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 816
    .line 817
    .line 818
    move-result-object v4

    .line 819
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->f(ILjava/util/List;)I

    .line 820
    .line 821
    .line 822
    move-result v4

    .line 823
    goto/16 :goto_1

    .line 824
    .line 825
    :pswitch_25
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 826
    .line 827
    .line 828
    move-result-object v4

    .line 829
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->d(ILjava/util/List;)I

    .line 830
    .line 831
    .line 832
    move-result v4

    .line 833
    goto/16 :goto_1

    .line 834
    .line 835
    :pswitch_26
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 836
    .line 837
    .line 838
    move-result-object v4

    .line 839
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->b(ILjava/util/List;)I

    .line 840
    .line 841
    .line 842
    move-result v4

    .line 843
    goto/16 :goto_1

    .line 844
    .line 845
    :pswitch_27
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 846
    .line 847
    .line 848
    move-result-object v4

    .line 849
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->r(ILjava/util/List;)I

    .line 850
    .line 851
    .line 852
    move-result v4

    .line 853
    goto/16 :goto_1

    .line 854
    .line 855
    :pswitch_28
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 856
    .line 857
    .line 858
    move-result-object v4

    .line 859
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->a(ILjava/util/List;)I

    .line 860
    .line 861
    .line 862
    move-result v4

    .line 863
    goto/16 :goto_1

    .line 864
    .line 865
    :pswitch_29
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 866
    .line 867
    .line 868
    move-result-object v4

    .line 869
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 870
    .line 871
    .line 872
    move-result-object v5

    .line 873
    invoke-static {v7, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/b1;->l(ILjava/util/List;Lcom/google/crypto/tink/shaded/protobuf/a1;)I

    .line 874
    .line 875
    .line 876
    move-result v4

    .line 877
    goto/16 :goto_1

    .line 878
    .line 879
    :pswitch_2a
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 880
    .line 881
    .line 882
    move-result-object v4

    .line 883
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->q(ILjava/util/List;)I

    .line 884
    .line 885
    .line 886
    move-result v4

    .line 887
    goto/16 :goto_1

    .line 888
    .line 889
    :pswitch_2b
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 890
    .line 891
    .line 892
    move-result-object v4

    .line 893
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 894
    .line 895
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 896
    .line 897
    .line 898
    move-result v4

    .line 899
    if-nez v4, :cond_5

    .line 900
    .line 901
    move v5, v1

    .line 902
    goto/16 :goto_3

    .line 903
    .line 904
    :cond_5
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 905
    .line 906
    .line 907
    move-result v5

    .line 908
    add-int/2addr v5, v12

    .line 909
    mul-int/2addr v5, v4

    .line 910
    goto/16 :goto_3

    .line 911
    .line 912
    :pswitch_2c
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 913
    .line 914
    .line 915
    move-result-object v4

    .line 916
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->d(ILjava/util/List;)I

    .line 917
    .line 918
    .line 919
    move-result v4

    .line 920
    goto/16 :goto_1

    .line 921
    .line 922
    :pswitch_2d
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 923
    .line 924
    .line 925
    move-result-object v4

    .line 926
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->f(ILjava/util/List;)I

    .line 927
    .line 928
    .line 929
    move-result v4

    .line 930
    goto/16 :goto_1

    .line 931
    .line 932
    :pswitch_2e
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 933
    .line 934
    .line 935
    move-result-object v4

    .line 936
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->h(ILjava/util/List;)I

    .line 937
    .line 938
    .line 939
    move-result v4

    .line 940
    goto/16 :goto_1

    .line 941
    .line 942
    :pswitch_2f
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 943
    .line 944
    .line 945
    move-result-object v4

    .line 946
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->t(ILjava/util/List;)I

    .line 947
    .line 948
    .line 949
    move-result v4

    .line 950
    goto/16 :goto_1

    .line 951
    .line 952
    :pswitch_30
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 953
    .line 954
    .line 955
    move-result-object v4

    .line 956
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->j(ILjava/util/List;)I

    .line 957
    .line 958
    .line 959
    move-result v4

    .line 960
    goto/16 :goto_1

    .line 961
    .line 962
    :pswitch_31
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 963
    .line 964
    .line 965
    move-result-object v4

    .line 966
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->d(ILjava/util/List;)I

    .line 967
    .line 968
    .line 969
    move-result v4

    .line 970
    goto/16 :goto_1

    .line 971
    .line 972
    :pswitch_32
    invoke-static {v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->t(JLjava/lang/Object;)Ljava/util/List;

    .line 973
    .line 974
    .line 975
    move-result-object v4

    .line 976
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/b1;->f(ILjava/util/List;)I

    .line 977
    .line 978
    .line 979
    move-result v4

    .line 980
    goto/16 :goto_1

    .line 981
    .line 982
    :pswitch_33
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 983
    .line 984
    .line 985
    move-result v4

    .line 986
    if-eqz v4, :cond_8

    .line 987
    .line 988
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 989
    .line 990
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 991
    .line 992
    .line 993
    move-result-object v4

    .line 994
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 995
    .line 996
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 997
    .line 998
    .line 999
    move-result-object v5

    .line 1000
    invoke-static {v7, v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/k;->D(ILcom/google/crypto/tink/shaded/protobuf/a;Lcom/google/crypto/tink/shaded/protobuf/a1;)I

    .line 1001
    .line 1002
    .line 1003
    move-result v4

    .line 1004
    goto/16 :goto_1

    .line 1005
    .line 1006
    :pswitch_34
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1007
    .line 1008
    .line 1009
    move-result v4

    .line 1010
    if-eqz v4, :cond_8

    .line 1011
    .line 1012
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1013
    .line 1014
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 1015
    .line 1016
    .line 1017
    move-result-wide v8

    .line 1018
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1019
    .line 1020
    .line 1021
    move-result v4

    .line 1022
    shl-long v6, v8, v12

    .line 1023
    .line 1024
    shr-long/2addr v8, v5

    .line 1025
    xor-long v5, v6, v8

    .line 1026
    .line 1027
    invoke-static {v5, v6}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 1028
    .line 1029
    .line 1030
    move-result v5

    .line 1031
    goto/16 :goto_2

    .line 1032
    .line 1033
    :pswitch_35
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1034
    .line 1035
    .line 1036
    move-result v4

    .line 1037
    if-eqz v4, :cond_8

    .line 1038
    .line 1039
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1040
    .line 1041
    invoke-virtual {v4, v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1042
    .line 1043
    .line 1044
    move-result v4

    .line 1045
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1046
    .line 1047
    .line 1048
    move-result v5

    .line 1049
    shl-int/lit8 v6, v4, 0x1

    .line 1050
    .line 1051
    shr-int/lit8 v4, v4, 0x1f

    .line 1052
    .line 1053
    xor-int/2addr v4, v6

    .line 1054
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 1055
    .line 1056
    .line 1057
    move-result v4

    .line 1058
    goto/16 :goto_4

    .line 1059
    .line 1060
    :pswitch_36
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1061
    .line 1062
    .line 1063
    move-result v4

    .line 1064
    if-eqz v4, :cond_8

    .line 1065
    .line 1066
    invoke-static {v7, v11, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1067
    .line 1068
    .line 1069
    move-result v3

    .line 1070
    goto/16 :goto_9

    .line 1071
    .line 1072
    :pswitch_37
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1073
    .line 1074
    .line 1075
    move-result v4

    .line 1076
    if-eqz v4, :cond_8

    .line 1077
    .line 1078
    invoke-static {v7, v10, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1079
    .line 1080
    .line 1081
    move-result v3

    .line 1082
    goto/16 :goto_9

    .line 1083
    .line 1084
    :pswitch_38
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1085
    .line 1086
    .line 1087
    move-result v4

    .line 1088
    if-eqz v4, :cond_8

    .line 1089
    .line 1090
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1091
    .line 1092
    invoke-virtual {v4, v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1093
    .line 1094
    .line 1095
    move-result v4

    .line 1096
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1097
    .line 1098
    .line 1099
    move-result v5

    .line 1100
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->E(I)I

    .line 1101
    .line 1102
    .line 1103
    move-result v4

    .line 1104
    goto/16 :goto_4

    .line 1105
    .line 1106
    :pswitch_39
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1107
    .line 1108
    .line 1109
    move-result v4

    .line 1110
    if-eqz v4, :cond_8

    .line 1111
    .line 1112
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1113
    .line 1114
    invoke-virtual {v4, v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1115
    .line 1116
    .line 1117
    move-result v4

    .line 1118
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1119
    .line 1120
    .line 1121
    move-result v5

    .line 1122
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->H(I)I

    .line 1123
    .line 1124
    .line 1125
    move-result v4

    .line 1126
    goto/16 :goto_4

    .line 1127
    .line 1128
    :pswitch_3a
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1129
    .line 1130
    .line 1131
    move-result v4

    .line 1132
    if-eqz v4, :cond_8

    .line 1133
    .line 1134
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1135
    .line 1136
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v4

    .line 1140
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 1141
    .line 1142
    invoke-static {v7, v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->z(ILcom/google/crypto/tink/shaded/protobuf/i;)I

    .line 1143
    .line 1144
    .line 1145
    move-result v4

    .line 1146
    goto/16 :goto_1

    .line 1147
    .line 1148
    :pswitch_3b
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1149
    .line 1150
    .line 1151
    move-result v5

    .line 1152
    if-eqz v5, :cond_8

    .line 1153
    .line 1154
    sget-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1155
    .line 1156
    invoke-virtual {v5, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v5

    .line 1160
    invoke-virtual {p0, v2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->o(I)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 1161
    .line 1162
    .line 1163
    move-result-object v6

    .line 1164
    sget-object v8, Lcom/google/crypto/tink/shaded/protobuf/b1;->a:Ljava/lang/Class;

    .line 1165
    .line 1166
    check-cast v5, Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 1167
    .line 1168
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1169
    .line 1170
    .line 1171
    move-result v7

    .line 1172
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1173
    .line 1174
    .line 1175
    move-object v8, v5

    .line 1176
    check-cast v8, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1177
    .line 1178
    iget v9, v8, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 1179
    .line 1180
    if-ne v9, v4, :cond_6

    .line 1181
    .line 1182
    invoke-interface {v6, v5}, Lcom/google/crypto/tink/shaded/protobuf/a1;->i(Lcom/google/crypto/tink/shaded/protobuf/a;)I

    .line 1183
    .line 1184
    .line 1185
    move-result v9

    .line 1186
    iput v9, v8, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 1187
    .line 1188
    :cond_6
    invoke-static {v9, v9, v7, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 1189
    .line 1190
    .line 1191
    move-result v3

    .line 1192
    goto/16 :goto_9

    .line 1193
    .line 1194
    :pswitch_3c
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1195
    .line 1196
    .line 1197
    move-result v4

    .line 1198
    if-eqz v4, :cond_8

    .line 1199
    .line 1200
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1201
    .line 1202
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 1203
    .line 1204
    .line 1205
    move-result-object v4

    .line 1206
    instance-of v5, v4, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 1207
    .line 1208
    if-eqz v5, :cond_7

    .line 1209
    .line 1210
    check-cast v4, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 1211
    .line 1212
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1213
    .line 1214
    .line 1215
    move-result v5

    .line 1216
    invoke-virtual {v4}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 1217
    .line 1218
    .line 1219
    move-result v4

    .line 1220
    invoke-static {v4, v4, v5, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->A(IIII)I

    .line 1221
    .line 1222
    .line 1223
    move-result v3

    .line 1224
    goto/16 :goto_9

    .line 1225
    .line 1226
    :cond_7
    check-cast v4, Ljava/lang/String;

    .line 1227
    .line 1228
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1229
    .line 1230
    .line 1231
    move-result v5

    .line 1232
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->F(Ljava/lang/String;)I

    .line 1233
    .line 1234
    .line 1235
    move-result v4

    .line 1236
    goto/16 :goto_5

    .line 1237
    .line 1238
    :pswitch_3d
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1239
    .line 1240
    .line 1241
    move-result v4

    .line 1242
    if-eqz v4, :cond_8

    .line 1243
    .line 1244
    invoke-static {v7, v12, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1245
    .line 1246
    .line 1247
    move-result v3

    .line 1248
    goto/16 :goto_9

    .line 1249
    .line 1250
    :pswitch_3e
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1251
    .line 1252
    .line 1253
    move-result v4

    .line 1254
    if-eqz v4, :cond_8

    .line 1255
    .line 1256
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->B(I)I

    .line 1257
    .line 1258
    .line 1259
    move-result v4

    .line 1260
    goto/16 :goto_1

    .line 1261
    .line 1262
    :pswitch_3f
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1263
    .line 1264
    .line 1265
    move-result v4

    .line 1266
    if-eqz v4, :cond_8

    .line 1267
    .line 1268
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->C(I)I

    .line 1269
    .line 1270
    .line 1271
    move-result v4

    .line 1272
    goto/16 :goto_1

    .line 1273
    .line 1274
    :pswitch_40
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1275
    .line 1276
    .line 1277
    move-result v4

    .line 1278
    if-eqz v4, :cond_8

    .line 1279
    .line 1280
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1281
    .line 1282
    invoke-virtual {v4, v8, v9, p1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 1283
    .line 1284
    .line 1285
    move-result v4

    .line 1286
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1287
    .line 1288
    .line 1289
    move-result v5

    .line 1290
    invoke-static {v4}, Lcom/google/crypto/tink/shaded/protobuf/k;->E(I)I

    .line 1291
    .line 1292
    .line 1293
    move-result v4

    .line 1294
    goto/16 :goto_4

    .line 1295
    .line 1296
    :pswitch_41
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1297
    .line 1298
    .line 1299
    move-result v4

    .line 1300
    if-eqz v4, :cond_8

    .line 1301
    .line 1302
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1303
    .line 1304
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 1305
    .line 1306
    .line 1307
    move-result-wide v4

    .line 1308
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1309
    .line 1310
    .line 1311
    move-result v6

    .line 1312
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 1313
    .line 1314
    .line 1315
    move-result v4

    .line 1316
    goto/16 :goto_6

    .line 1317
    .line 1318
    :pswitch_42
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1319
    .line 1320
    .line 1321
    move-result v4

    .line 1322
    if-eqz v4, :cond_8

    .line 1323
    .line 1324
    sget-object v4, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 1325
    .line 1326
    invoke-virtual {v4, p1, v8, v9}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 1327
    .line 1328
    .line 1329
    move-result-wide v4

    .line 1330
    invoke-static {v7}, Lcom/google/crypto/tink/shaded/protobuf/k;->G(I)I

    .line 1331
    .line 1332
    .line 1333
    move-result v6

    .line 1334
    invoke-static {v4, v5}, Lcom/google/crypto/tink/shaded/protobuf/k;->I(J)I

    .line 1335
    .line 1336
    .line 1337
    move-result v4

    .line 1338
    goto/16 :goto_6

    .line 1339
    .line 1340
    :pswitch_43
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1341
    .line 1342
    .line 1343
    move-result v4

    .line 1344
    if-eqz v4, :cond_8

    .line 1345
    .line 1346
    invoke-static {v7, v10, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1347
    .line 1348
    .line 1349
    move-result v3

    .line 1350
    goto :goto_9

    .line 1351
    :pswitch_44
    invoke-virtual {p0, v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 1352
    .line 1353
    .line 1354
    move-result v4

    .line 1355
    if-eqz v4, :cond_8

    .line 1356
    .line 1357
    invoke-static {v7, v11, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->a(III)I

    .line 1358
    .line 1359
    .line 1360
    move-result v3

    .line 1361
    :cond_8
    :goto_9
    add-int/lit8 v2, v2, 0x3

    .line 1362
    .line 1363
    goto/16 :goto_0

    .line 1364
    .line 1365
    :cond_9
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->m:Lcom/google/crypto/tink/shaded/protobuf/d1;

    .line 1366
    .line 1367
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1368
    .line 1369
    .line 1370
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 1371
    .line 1372
    iget-object p0, p1, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 1373
    .line 1374
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/c1;->a()I

    .line 1375
    .line 1376
    .line 1377
    move-result p0

    .line 1378
    add-int/2addr p0, v3

    .line 1379
    return p0

    .line 1380
    nop

    .line 1381
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_44
        :pswitch_43
        :pswitch_42
        :pswitch_41
        :pswitch_40
        :pswitch_3f
        :pswitch_3e
        :pswitch_3d
        :pswitch_3c
        :pswitch_3b
        :pswitch_3a
        :pswitch_39
        :pswitch_38
        :pswitch_37
        :pswitch_36
        :pswitch_35
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final r(ILjava/lang/Object;)Z
    .locals 5

    .line 1
    iget-boolean v0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->g:Z

    .line 2
    .line 3
    const v1, 0xfffff

    .line 4
    .line 5
    .line 6
    const/4 v2, 0x1

    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    and-int p1, p0, v1

    .line 14
    .line 15
    int-to-long v0, p1

    .line 16
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/r0;->N(I)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    const-wide/16 v3, 0x0

    .line 21
    .line 22
    packed-switch p0, :pswitch_data_0

    .line 23
    .line 24
    .line 25
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :pswitch_0
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 32
    .line 33
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    if-eqz p0, :cond_3

    .line 38
    .line 39
    goto/16 :goto_0

    .line 40
    .line 41
    :pswitch_1
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 42
    .line 43
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 44
    .line 45
    .line 46
    move-result-wide p0

    .line 47
    cmp-long p0, p0, v3

    .line 48
    .line 49
    if-eqz p0, :cond_3

    .line 50
    .line 51
    goto/16 :goto_0

    .line 52
    .line 53
    :pswitch_2
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 54
    .line 55
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    if-eqz p0, :cond_3

    .line 60
    .line 61
    goto/16 :goto_0

    .line 62
    .line 63
    :pswitch_3
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 64
    .line 65
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 66
    .line 67
    .line 68
    move-result-wide p0

    .line 69
    cmp-long p0, p0, v3

    .line 70
    .line 71
    if-eqz p0, :cond_3

    .line 72
    .line 73
    goto/16 :goto_0

    .line 74
    .line 75
    :pswitch_4
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 76
    .line 77
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    if-eqz p0, :cond_3

    .line 82
    .line 83
    goto/16 :goto_0

    .line 84
    .line 85
    :pswitch_5
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 86
    .line 87
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    if-eqz p0, :cond_3

    .line 92
    .line 93
    goto/16 :goto_0

    .line 94
    .line 95
    :pswitch_6
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 96
    .line 97
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    if-eqz p0, :cond_3

    .line 102
    .line 103
    goto/16 :goto_0

    .line 104
    .line 105
    :pswitch_7
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/i;->e:Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 106
    .line 107
    sget-object p1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 108
    .line 109
    invoke-virtual {p1, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/h;->equals(Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result p0

    .line 117
    xor-int/2addr p0, v2

    .line 118
    return p0

    .line 119
    :pswitch_8
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 120
    .line 121
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    if-eqz p0, :cond_3

    .line 126
    .line 127
    goto/16 :goto_0

    .line 128
    .line 129
    :pswitch_9
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 130
    .line 131
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    instance-of p1, p0, Ljava/lang/String;

    .line 136
    .line 137
    if-eqz p1, :cond_0

    .line 138
    .line 139
    check-cast p0, Ljava/lang/String;

    .line 140
    .line 141
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 142
    .line 143
    .line 144
    move-result p0

    .line 145
    xor-int/2addr p0, v2

    .line 146
    return p0

    .line 147
    :cond_0
    instance-of p1, p0, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 148
    .line 149
    if-eqz p1, :cond_1

    .line 150
    .line 151
    sget-object p1, Lcom/google/crypto/tink/shaded/protobuf/i;->e:Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 152
    .line 153
    invoke-virtual {p1, p0}, Lcom/google/crypto/tink/shaded/protobuf/h;->equals(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    move-result p0

    .line 157
    xor-int/2addr p0, v2

    .line 158
    return p0

    .line 159
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 160
    .line 161
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 162
    .line 163
    .line 164
    throw p0

    .line 165
    :pswitch_a
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 166
    .line 167
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->c(JLjava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    return p0

    .line 172
    :pswitch_b
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 173
    .line 174
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 175
    .line 176
    .line 177
    move-result p0

    .line 178
    if-eqz p0, :cond_3

    .line 179
    .line 180
    goto :goto_0

    .line 181
    :pswitch_c
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 182
    .line 183
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 184
    .line 185
    .line 186
    move-result-wide p0

    .line 187
    cmp-long p0, p0, v3

    .line 188
    .line 189
    if-eqz p0, :cond_3

    .line 190
    .line 191
    goto :goto_0

    .line 192
    :pswitch_d
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 193
    .line 194
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 195
    .line 196
    .line 197
    move-result p0

    .line 198
    if-eqz p0, :cond_3

    .line 199
    .line 200
    goto :goto_0

    .line 201
    :pswitch_e
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 202
    .line 203
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 204
    .line 205
    .line 206
    move-result-wide p0

    .line 207
    cmp-long p0, p0, v3

    .line 208
    .line 209
    if-eqz p0, :cond_3

    .line 210
    .line 211
    goto :goto_0

    .line 212
    :pswitch_f
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 213
    .line 214
    invoke-virtual {p0, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->h(Ljava/lang/Object;J)J

    .line 215
    .line 216
    .line 217
    move-result-wide p0

    .line 218
    cmp-long p0, p0, v3

    .line 219
    .line 220
    if-eqz p0, :cond_3

    .line 221
    .line 222
    goto :goto_0

    .line 223
    :pswitch_10
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 224
    .line 225
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->f(JLjava/lang/Object;)F

    .line 226
    .line 227
    .line 228
    move-result p0

    .line 229
    const/4 p1, 0x0

    .line 230
    cmpl-float p0, p0, p1

    .line 231
    .line 232
    if-eqz p0, :cond_3

    .line 233
    .line 234
    goto :goto_0

    .line 235
    :pswitch_11
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 236
    .line 237
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->e(JLjava/lang/Object;)D

    .line 238
    .line 239
    .line 240
    move-result-wide p0

    .line 241
    const-wide/16 v0, 0x0

    .line 242
    .line 243
    cmpl-double p0, p0, v0

    .line 244
    .line 245
    if-eqz p0, :cond_3

    .line 246
    .line 247
    goto :goto_0

    .line 248
    :cond_2
    add-int/lit8 p1, p1, 0x2

    .line 249
    .line 250
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 251
    .line 252
    aget p0, p0, p1

    .line 253
    .line 254
    ushr-int/lit8 p1, p0, 0x14

    .line 255
    .line 256
    shl-int p1, v2, p1

    .line 257
    .line 258
    and-int/2addr p0, v1

    .line 259
    int-to-long v0, p0

    .line 260
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 261
    .line 262
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 263
    .line 264
    .line 265
    move-result p0

    .line 266
    and-int/2addr p0, p1

    .line 267
    if-eqz p0, :cond_3

    .line 268
    .line 269
    :goto_0
    return v2

    .line 270
    :cond_3
    const/4 p0, 0x0

    .line 271
    return p0

    .line 272
    nop

    .line 273
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final s(ILjava/lang/Object;I)Z
    .locals 2

    .line 1
    add-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 4
    .line 5
    aget p0, p0, p3

    .line 6
    .line 7
    const p3, 0xfffff

    .line 8
    .line 9
    .line 10
    and-int/2addr p0, p3

    .line 11
    int-to-long v0, p0

    .line 12
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 13
    .line 14
    invoke-virtual {p0, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-ne p0, p1, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public final u(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 3

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const v0, 0xfffff

    .line 6
    .line 7
    .line 8
    and-int/2addr p1, v0

    .line 9
    int-to-long v0, p1

    .line 10
    sget-object p1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 11
    .line 12
    invoke-virtual {p1, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iget-object p0, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->n:Lcom/google/crypto/tink/shaded/protobuf/n0;

    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    move-object v2, p1

    .line 24
    check-cast v2, Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 25
    .line 26
    iget-boolean v2, v2, Lcom/google/crypto/tink/shaded/protobuf/m0;->d:Z

    .line 27
    .line 28
    if-nez v2, :cond_1

    .line 29
    .line 30
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/m0;->e:Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 31
    .line 32
    invoke-virtual {v2}, Lcom/google/crypto/tink/shaded/protobuf/m0;->c()Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    invoke-static {v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/n0;->b(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 37
    .line 38
    .line 39
    invoke-static {p2, v0, v1, v2}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    move-object p1, v2

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    sget-object p1, Lcom/google/crypto/tink/shaded/protobuf/m0;->e:Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 48
    .line 49
    invoke-virtual {p1}, Lcom/google/crypto/tink/shaded/protobuf/m0;->c()Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-static {p2, v0, v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_1
    :goto_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/m0;

    .line 60
    .line 61
    invoke-static {p3}, Lf2/m0;->u(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    const/4 p0, 0x0

    .line 65
    throw p0
.end method

.method public final v(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 4

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const v1, 0xfffff

    .line 6
    .line 7
    .line 8
    and-int/2addr v0, v1

    .line 9
    int-to-long v0, v0

    .line 10
    invoke-virtual {p0, p1, p3}, Lcom/google/crypto/tink/shaded/protobuf/r0;->r(ILjava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 18
    .line 19
    invoke-virtual {v2, p2, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    invoke-virtual {v2, p3, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p3

    .line 27
    if-eqz v3, :cond_1

    .line 28
    .line 29
    if-eqz p3, :cond_1

    .line 30
    .line 31
    invoke-static {v3, p3}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 32
    .line 33
    .line 34
    move-result-object p3

    .line 35
    invoke-static {p2, v0, v1, p3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_1
    if-eqz p3, :cond_2

    .line 43
    .line 44
    invoke-static {p2, v0, v1, p3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, p1, p2}, Lcom/google/crypto/tink/shaded/protobuf/r0;->K(ILjava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :cond_2
    :goto_0
    return-void
.end method

.method public final w(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 5

    .line 1
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->O(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Lcom/google/crypto/tink/shaded/protobuf/r0;->a:[I

    .line 6
    .line 7
    aget v1, v1, p1

    .line 8
    .line 9
    const v2, 0xfffff

    .line 10
    .line 11
    .line 12
    and-int/2addr v0, v2

    .line 13
    int-to-long v2, v0

    .line 14
    invoke-virtual {p0, v1, p3, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->s(ILjava/lang/Object;I)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 22
    .line 23
    invoke-virtual {v0, p2, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    invoke-virtual {v0, p3, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/k1;->i(Ljava/lang/Object;J)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p3

    .line 31
    if-eqz v4, :cond_1

    .line 32
    .line 33
    if-eqz p3, :cond_1

    .line 34
    .line 35
    invoke-static {v4, p3}, Lcom/google/crypto/tink/shaded/protobuf/b0;->c(Ljava/lang/Object;Ljava/lang/Object;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 36
    .line 37
    .line 38
    move-result-object p3

    .line 39
    invoke-static {p2, v2, v3, p3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p0, v1, p2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :cond_1
    if-eqz p3, :cond_2

    .line 47
    .line 48
    invoke-static {p2, v2, v3, p3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->o(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, v1, p2, p1}, Lcom/google/crypto/tink/shaded/protobuf/r0;->L(ILjava/lang/Object;I)V

    .line 52
    .line 53
    .line 54
    :cond_2
    :goto_0
    return-void
.end method
