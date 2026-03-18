.class public final Lpw0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;


# instance fields
.field public final synthetic d:I

.field public final e:Lpx0/g;


# direct methods
.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x2

    iput v0, p0, Lpw0/a;->d:I

    .line 38
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 39
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    move-result-object v0

    .line 40
    sget-object v1, Lvy0/p0;->a:Lcz0/e;

    .line 41
    invoke-static {v0, v1}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    move-result-object v0

    .line 42
    iput-object v0, p0, Lpw0/a;->e:Lpx0/g;

    return-void
.end method

.method public constructor <init>(Lpx0/g;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lpw0/a;->d:I

    .line 43
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 44
    iput-object p1, p0, Lpw0/a;->e:Lpx0/g;

    return-void
.end method

.method public constructor <init>(Lpx0/g;Lio/ktor/utils/io/t;Ljava/lang/String;Ljava/lang/Long;)V
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    const/4 v4, 0x0

    iput v4, v0, Lpw0/a;->d:I

    .line 1
    const-string v5, "coroutineContext"

    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "channel"

    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object v1, v0, Lpw0/a;->e:Lpx0/g;

    .line 4
    sget-object v1, Lpw0/m;->a:Loz0/a;

    .line 5
    sget-object v1, Low0/c;->a:Low0/e;

    .line 6
    const-string v1, "multipart/"

    const/4 v5, 0x1

    invoke-static {v3, v1, v5}, Lly0/p;->Z(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    move-result v1

    if-eqz v1, :cond_19

    .line 7
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v1

    move v6, v4

    move v7, v6

    move v8, v7

    :goto_0
    const/4 v9, 0x3

    const/16 v11, 0x5c

    const/16 v13, 0x2c

    const/16 v14, 0x22

    const/4 v15, 0x4

    const/4 v4, 0x2

    const/16 v10, 0x3b

    if-ge v6, v1, :cond_d

    .line 8
    invoke-virtual {v3, v6}, Ljava/lang/String;->charAt(I)C

    move-result v12

    if-eqz v7, :cond_b

    if-eq v7, v5, :cond_6

    if-eq v7, v4, :cond_4

    if-eq v7, v9, :cond_1

    if-eq v7, v15, :cond_0

    goto :goto_5

    :cond_0
    move v7, v9

    goto :goto_5

    :cond_1
    if-eq v12, v14, :cond_3

    if-eq v12, v11, :cond_2

    goto :goto_5

    :cond_2
    move v7, v15

    goto :goto_5

    :cond_3
    :goto_1
    move v7, v5

    :goto_2
    const/4 v8, 0x0

    goto :goto_5

    :cond_4
    if-eq v12, v14, :cond_0

    if-eq v12, v13, :cond_5

    if-eq v12, v10, :cond_3

    goto :goto_5

    :cond_5
    :goto_3
    const/4 v7, 0x0

    goto :goto_5

    :cond_6
    const/16 v15, 0x3d

    if-ne v12, v15, :cond_7

    move v7, v4

    goto :goto_5

    :cond_7
    if-ne v12, v10, :cond_8

    goto :goto_2

    :cond_8
    if-ne v12, v13, :cond_9

    goto :goto_3

    :cond_9
    const/16 v15, 0x20

    if-eq v12, v15, :cond_c

    if-nez v8, :cond_a

    .line 9
    const-string v12, "boundary="

    invoke-static {v3, v12, v6, v5}, Lly0/p;->a0(Ljava/lang/CharSequence;Ljava/lang/String;IZ)Z

    move-result v12

    if-eqz v12, :cond_a

    :goto_4
    const/4 v1, -0x1

    goto :goto_6

    :cond_a
    add-int/lit8 v8, v8, 0x1

    goto :goto_5

    :cond_b
    if-ne v12, v10, :cond_c

    goto :goto_1

    :cond_c
    :goto_5
    add-int/lit8 v6, v6, 0x1

    const/4 v4, 0x0

    goto :goto_0

    :cond_d
    const/4 v6, -0x1

    goto :goto_4

    :goto_6
    if-eq v6, v1, :cond_18

    add-int/lit8 v6, v6, 0x9

    const/16 v1, 0x4a

    .line 10
    new-array v1, v1, [B

    .line 11
    new-instance v7, Lkotlin/jvm/internal/d0;

    .line 12
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    const/16 v8, 0xd

    .line 13
    invoke-static {v7, v1, v8}, Lpw0/m;->c(Lkotlin/jvm/internal/d0;[BB)V

    const/16 v8, 0xa

    .line 14
    invoke-static {v7, v1, v8}, Lpw0/m;->c(Lkotlin/jvm/internal/d0;[BB)V

    const/16 v8, 0x2d

    .line 15
    invoke-static {v7, v1, v8}, Lpw0/m;->c(Lkotlin/jvm/internal/d0;[BB)V

    .line 16
    invoke-static {v7, v1, v8}, Lpw0/m;->c(Lkotlin/jvm/internal/d0;[BB)V

    .line 17
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v8

    const/4 v12, 0x0

    :goto_7
    if-ge v6, v8, :cond_16

    .line 18
    invoke-virtual {v3, v6}, Ljava/lang/String;->charAt(I)C

    move-result v15

    const v16, 0xffff

    and-int v10, v15, v16

    const/16 v13, 0x7f

    if-gt v10, v13, :cond_15

    if-eqz v12, :cond_12

    if-eq v12, v5, :cond_11

    if-eq v12, v4, :cond_f

    if-eq v12, v9, :cond_e

    goto :goto_8

    :cond_e
    int-to-byte v10, v10

    .line 19
    invoke-static {v7, v1, v10}, Lpw0/m;->c(Lkotlin/jvm/internal/d0;[BB)V

    move v12, v4

    :goto_8
    const/16 v4, 0x2c

    const/16 v5, 0x3b

    const/16 v13, 0x20

    goto :goto_9

    :cond_f
    if-eq v15, v14, :cond_16

    if-eq v15, v11, :cond_10

    int-to-byte v10, v10

    .line 20
    invoke-static {v7, v1, v10}, Lpw0/m;->c(Lkotlin/jvm/internal/d0;[BB)V

    goto :goto_8

    :cond_10
    move v12, v9

    goto :goto_8

    :cond_11
    const/16 v13, 0x20

    if-eq v15, v13, :cond_16

    const/16 v4, 0x2c

    if-eq v15, v4, :cond_16

    const/16 v5, 0x3b

    if-eq v15, v5, :cond_16

    int-to-byte v10, v10

    .line 21
    invoke-static {v7, v1, v10}, Lpw0/m;->c(Lkotlin/jvm/internal/d0;[BB)V

    goto :goto_9

    :cond_12
    const/16 v4, 0x2c

    const/16 v5, 0x3b

    const/16 v13, 0x20

    if-eq v15, v13, :cond_14

    if-eq v15, v14, :cond_13

    if-eq v15, v4, :cond_16

    if-eq v15, v5, :cond_16

    int-to-byte v10, v10

    .line 22
    invoke-static {v7, v1, v10}, Lpw0/m;->c(Lkotlin/jvm/internal/d0;[BB)V

    const/4 v12, 0x1

    goto :goto_9

    :cond_13
    const/4 v12, 0x2

    :cond_14
    :goto_9
    add-int/lit8 v6, v6, 0x1

    move v13, v4

    move v10, v5

    const/4 v4, 0x2

    const/4 v5, 0x1

    goto :goto_7

    .line 23
    :cond_15
    new-instance v0, Ljava/io/IOException;

    .line 24
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Failed to parse multipart: wrong boundary byte 0x"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const/16 v2, 0x10

    invoke-static {v2}, Lry/a;->a(I)V

    invoke-static {v10, v2}, Ljava/lang/Integer;->toString(II)Ljava/lang/String;

    move-result-object v2

    const-string v3, "toString(...)"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " - should be 7bit character"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 25
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 26
    :cond_16
    iget v3, v7, Lkotlin/jvm/internal/d0;->d:I

    const/4 v4, 0x4

    if-eq v3, v4, :cond_17

    const/4 v4, 0x0

    .line 27
    invoke-static {v1, v4, v3}, Lmx0/n;->n([BII)[B

    move-result-object v1

    .line 28
    new-instance v3, Loz0/a;

    .line 29
    array-length v5, v1

    invoke-direct {v3, v1, v4, v5}, Loz0/a;-><init>([BII)V

    .line 30
    new-instance v1, Lpw0/i;

    const/4 v5, 0x0

    move-object/from16 v6, p4

    invoke-direct {v1, v2, v3, v6, v5}, Lpw0/i;-><init>(Lio/ktor/utils/io/t;Loz0/a;Ljava/lang/Long;Lkotlin/coroutines/Continuation;)V

    invoke-static {v0, v4, v1, v9}, Llp/mf;->c(Lvy0/b0;ILay0/n;I)Lxy0/w;

    return-void

    .line 31
    :cond_17
    new-instance v0, Ljava/io/IOException;

    const-string v1, "Empty multipart boundary is not allowed"

    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 32
    :cond_18
    new-instance v0, Ljava/io/IOException;

    const-string v1, "Failed to parse multipart: Content-Type\'s boundary parameter is missing"

    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 33
    :cond_19
    new-instance v0, Lio/ktor/utils/io/k0;

    .line 34
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Failed to parse multipart: Content-Type should be multipart/* but it is "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    .line 35
    const-string v2, "message"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 37
    throw v0
.end method


# virtual methods
.method public final getCoroutineContext()Lpx0/g;
    .locals 1

    .line 1
    iget v0, p0, Lpw0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lpw0/a;->e:Lpx0/g;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Lpw0/a;->e:Lpx0/g;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    iget-object p0, p0, Lpw0/a;->e:Lpx0/g;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lpw0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "CoroutineScope(coroutineContext="

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lpw0/a;->e:Lpx0/g;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const/16 p0, 0x29

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
