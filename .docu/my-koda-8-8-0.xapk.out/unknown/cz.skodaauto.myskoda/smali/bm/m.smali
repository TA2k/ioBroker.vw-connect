.class public final Lbm/m;
.super Ljava/io/InputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/io/InputStream;

.field public f:I


# direct methods
.method public synthetic constructor <init>(Ljava/io/InputStream;I)V
    .locals 0

    .line 1
    iput p2, p0, Lbm/m;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/io/InputStream;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lbm/m;->e:Ljava/io/InputStream;

    .line 7
    .line 8
    const/high16 p1, 0x40000000    # 2.0f

    .line 9
    .line 10
    iput p1, p0, Lbm/m;->f:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final available()I
    .locals 1

    .line 1
    iget v0, p0, Lbm/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Lbm/m;->f:I

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    iget p0, p0, Lbm/m;->f:I

    .line 10
    .line 11
    return p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final close()V
    .locals 1

    .line 1
    iget v0, p0, Lbm/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lbm/m;->e:Ljava/io/InputStream;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    iget-object p0, p0, Lbm/m;->e:Ljava/io/InputStream;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final read()I
    .locals 2

    iget v0, p0, Lbm/m;->d:I

    packed-switch v0, :pswitch_data_0

    .line 1
    iget-object v0, p0, Lbm/m;->e:Ljava/io/InputStream;

    invoke-virtual {v0}, Ljava/io/InputStream;->read()I

    move-result v0

    const/4 v1, -0x1

    if-ne v0, v1, :cond_0

    const/4 v1, 0x0

    .line 2
    iput v1, p0, Lbm/m;->f:I

    :cond_0
    return v0

    .line 3
    :pswitch_0
    iget-object v0, p0, Lbm/m;->e:Ljava/io/InputStream;

    invoke-virtual {v0}, Ljava/io/InputStream;->read()I

    move-result v0

    const/4 v1, -0x1

    if-ne v0, v1, :cond_1

    const/4 v1, 0x0

    .line 4
    iput v1, p0, Lbm/m;->f:I

    :cond_1
    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final read([B)I
    .locals 1

    iget v0, p0, Lbm/m;->d:I

    packed-switch v0, :pswitch_data_0

    .line 5
    iget-object v0, p0, Lbm/m;->e:Ljava/io/InputStream;

    invoke-virtual {v0, p1}, Ljava/io/InputStream;->read([B)I

    move-result p1

    const/4 v0, -0x1

    if-ne p1, v0, :cond_0

    const/4 v0, 0x0

    .line 6
    iput v0, p0, Lbm/m;->f:I

    :cond_0
    return p1

    .line 7
    :pswitch_0
    iget-object v0, p0, Lbm/m;->e:Ljava/io/InputStream;

    invoke-virtual {v0, p1}, Ljava/io/InputStream;->read([B)I

    move-result p1

    const/4 v0, -0x1

    if-ne p1, v0, :cond_1

    const/4 v0, 0x0

    .line 8
    iput v0, p0, Lbm/m;->f:I

    :cond_1
    return p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final read([BII)I
    .locals 1

    iget v0, p0, Lbm/m;->d:I

    packed-switch v0, :pswitch_data_0

    .line 9
    iget-object v0, p0, Lbm/m;->e:Ljava/io/InputStream;

    invoke-virtual {v0, p1, p2, p3}, Ljava/io/InputStream;->read([BII)I

    move-result p1

    const/4 p2, -0x1

    if-ne p1, p2, :cond_0

    const/4 p2, 0x0

    .line 10
    iput p2, p0, Lbm/m;->f:I

    :cond_0
    return p1

    .line 11
    :pswitch_0
    iget-object v0, p0, Lbm/m;->e:Ljava/io/InputStream;

    invoke-virtual {v0, p1, p2, p3}, Ljava/io/InputStream;->read([BII)I

    move-result p1

    const/4 p2, -0x1

    if-ne p1, p2, :cond_1

    const/4 p2, 0x0

    .line 12
    iput p2, p0, Lbm/m;->f:I

    :cond_1
    return p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final skip(J)J
    .locals 1

    .line 1
    iget v0, p0, Lbm/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lbm/m;->e:Ljava/io/InputStream;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Ljava/io/InputStream;->skip(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lbm/m;->e:Ljava/io/InputStream;

    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Ljava/io/InputStream;->skip(J)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
