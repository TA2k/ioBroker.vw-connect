.class public final Lcom/google/protobuf/j1;
.super Lcom/google/protobuf/l1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic b:I


# direct methods
.method public synthetic constructor <init>(Lsun/misc/Unsafe;I)V
    .locals 0

    .line 1
    iput p2, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lcom/google/protobuf/l1;-><init>(Lsun/misc/Unsafe;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c(JLjava/lang/Object;)Z
    .locals 2

    .line 1
    iget p0, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-boolean p0, Lcom/google/protobuf/m1;->g:Z

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/4 v1, 0x1

    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-static {p1, p2, p3}, Lcom/google/protobuf/m1;->h(JLjava/lang/Object;)B

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    :goto_0
    move v0, v1

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    invoke-static {p1, p2, p3}, Lcom/google/protobuf/m1;->i(JLjava/lang/Object;)B

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    :goto_1
    return v0

    .line 28
    :pswitch_0
    sget-boolean p0, Lcom/google/protobuf/m1;->g:Z

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    const/4 v1, 0x1

    .line 32
    if-eqz p0, :cond_2

    .line 33
    .line 34
    invoke-static {p1, p2, p3}, Lcom/google/protobuf/m1;->h(JLjava/lang/Object;)B

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_3

    .line 39
    .line 40
    :goto_2
    move v0, v1

    .line 41
    goto :goto_3

    .line 42
    :cond_2
    invoke-static {p1, p2, p3}, Lcom/google/protobuf/m1;->i(JLjava/lang/Object;)B

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_3

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_3
    :goto_3
    return v0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Ljava/lang/Object;J)B
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-boolean p0, Lcom/google/protobuf/m1;->g:Z

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-static {p2, p3, p1}, Lcom/google/protobuf/m1;->h(JLjava/lang/Object;)B

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-static {p2, p3, p1}, Lcom/google/protobuf/m1;->i(JLjava/lang/Object;)B

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    :goto_0
    return p0

    .line 20
    :pswitch_0
    sget-boolean p0, Lcom/google/protobuf/m1;->g:Z

    .line 21
    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    invoke-static {p2, p3, p1}, Lcom/google/protobuf/m1;->h(JLjava/lang/Object;)B

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-static {p2, p3, p1}, Lcom/google/protobuf/m1;->i(JLjava/lang/Object;)B

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    :goto_1
    return p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final e(JLjava/lang/Object;)D
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p3, p1, p2}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    invoke-static {p0, p1}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 11
    .line 12
    .line 13
    move-result-wide p0

    .line 14
    return-wide p0

    .line 15
    :pswitch_0
    invoke-virtual {p0, p3, p1, p2}, Lcom/google/protobuf/l1;->h(Ljava/lang/Object;J)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    invoke-static {p0, p1}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 20
    .line 21
    .line 22
    move-result-wide p0

    .line 23
    return-wide p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f(JLjava/lang/Object;)F
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/protobuf/l1;->g(JLjava/lang/Object;)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final k(Ljava/lang/Object;JZ)V
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-boolean p0, Lcom/google/protobuf/m1;->g:Z

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    int-to-byte p0, p4

    .line 11
    invoke-static {p1, p2, p3, p0}, Lcom/google/protobuf/m1;->l(Ljava/lang/Object;JB)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    int-to-byte p0, p4

    .line 16
    invoke-static {p1, p2, p3, p0}, Lcom/google/protobuf/m1;->m(Ljava/lang/Object;JB)V

    .line 17
    .line 18
    .line 19
    :goto_0
    return-void

    .line 20
    :pswitch_0
    sget-boolean p0, Lcom/google/protobuf/m1;->g:Z

    .line 21
    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    int-to-byte p0, p4

    .line 25
    invoke-static {p1, p2, p3, p0}, Lcom/google/protobuf/m1;->l(Ljava/lang/Object;JB)V

    .line 26
    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    int-to-byte p0, p4

    .line 30
    invoke-static {p1, p2, p3, p0}, Lcom/google/protobuf/m1;->m(Ljava/lang/Object;JB)V

    .line 31
    .line 32
    .line 33
    :goto_1
    return-void

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final l(Ljava/lang/Object;JB)V
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-boolean p0, Lcom/google/protobuf/m1;->g:Z

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-static {p1, p2, p3, p4}, Lcom/google/protobuf/m1;->l(Ljava/lang/Object;JB)V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-static {p1, p2, p3, p4}, Lcom/google/protobuf/m1;->m(Ljava/lang/Object;JB)V

    .line 15
    .line 16
    .line 17
    :goto_0
    return-void

    .line 18
    :pswitch_0
    sget-boolean p0, Lcom/google/protobuf/m1;->g:Z

    .line 19
    .line 20
    if-eqz p0, :cond_1

    .line 21
    .line 22
    invoke-static {p1, p2, p3, p4}, Lcom/google/protobuf/m1;->l(Ljava/lang/Object;JB)V

    .line 23
    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_1
    invoke-static {p1, p2, p3, p4}, Lcom/google/protobuf/m1;->m(Ljava/lang/Object;JB)V

    .line 27
    .line 28
    .line 29
    :goto_1
    return-void

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final m(Ljava/lang/Object;JD)V
    .locals 8

    .line 1
    iget v0, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p4, p5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 7
    .line 8
    .line 9
    move-result-wide p4

    .line 10
    move-wide v6, p2

    .line 11
    move-object p3, p1

    .line 12
    move-wide p1, v6

    .line 13
    invoke-virtual/range {p0 .. p5}, Lcom/google/protobuf/l1;->p(JLjava/lang/Object;J)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    move-wide v6, p2

    .line 18
    move-object p3, p1

    .line 19
    move-wide p1, v6

    .line 20
    invoke-static {p4, p5}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 21
    .line 22
    .line 23
    move-result-wide v4

    .line 24
    move-object v0, p0

    .line 25
    move-wide v1, p1

    .line 26
    move-object v3, p3

    .line 27
    invoke-virtual/range {v0 .. v5}, Lcom/google/protobuf/l1;->p(JLjava/lang/Object;J)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final n(Ljava/lang/Object;JF)V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p4}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 7
    .line 8
    .line 9
    move-result p4

    .line 10
    invoke-virtual {p0, p2, p3, p1, p4}, Lcom/google/protobuf/l1;->o(JLjava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    invoke-static {p4}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 15
    .line 16
    .line 17
    move-result p4

    .line 18
    invoke-virtual {p0, p2, p3, p1, p4}, Lcom/google/protobuf/l1;->o(JLjava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final s()Z
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/protobuf/j1;->b:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0

    .line 8
    :pswitch_0
    const/4 p0, 0x0

    .line 9
    return p0

    .line 10
    nop

    .line 11
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
