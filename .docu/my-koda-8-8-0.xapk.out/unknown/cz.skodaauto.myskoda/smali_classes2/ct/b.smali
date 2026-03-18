.class public final Lct/b;
.super Ljava/io/OutputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public e:J


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lct/b;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/io/OutputStream;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final write(I)V
    .locals 4

    iget p1, p0, Lct/b;->d:I

    packed-switch p1, :pswitch_data_0

    .line 1
    iget-wide v0, p0, Lct/b;->e:J

    const-wide/16 v2, 0x1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lct/b;->e:J

    return-void

    .line 2
    :pswitch_0
    iget-wide v0, p0, Lct/b;->e:J

    const-wide/16 v2, 0x1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lct/b;->e:J

    return-void

    .line 3
    :pswitch_1
    iget-wide v0, p0, Lct/b;->e:J

    const-wide/16 v2, 0x1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lct/b;->e:J

    return-void

    .line 4
    :pswitch_2
    iget-wide v0, p0, Lct/b;->e:J

    const-wide/16 v2, 0x1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lct/b;->e:J

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final write([B)V
    .locals 4

    iget v0, p0, Lct/b;->d:I

    packed-switch v0, :pswitch_data_0

    .line 5
    iget-wide v0, p0, Lct/b;->e:J

    array-length p1, p1

    int-to-long v2, p1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lct/b;->e:J

    return-void

    .line 6
    :pswitch_0
    iget-wide v0, p0, Lct/b;->e:J

    array-length p1, p1

    int-to-long v2, p1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lct/b;->e:J

    return-void

    .line 7
    :pswitch_1
    iget-wide v0, p0, Lct/b;->e:J

    array-length p1, p1

    int-to-long v2, p1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lct/b;->e:J

    return-void

    .line 8
    :pswitch_2
    iget-wide v0, p0, Lct/b;->e:J

    array-length p1, p1

    int-to-long v2, p1

    add-long/2addr v0, v2

    iput-wide v0, p0, Lct/b;->e:J

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final write([BII)V
    .locals 2

    iget v0, p0, Lct/b;->d:I

    packed-switch v0, :pswitch_data_0

    if-ltz p2, :cond_0

    .line 9
    array-length p1, p1

    if-gt p2, p1, :cond_0

    if-ltz p3, :cond_0

    add-int/2addr p2, p3

    if-gt p2, p1, :cond_0

    if-ltz p2, :cond_0

    .line 10
    iget-wide p1, p0, Lct/b;->e:J

    int-to-long v0, p3

    add-long/2addr p1, v0

    iput-wide p1, p0, Lct/b;->e:J

    return-void

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 12
    invoke-direct {p0}, Ljava/lang/IndexOutOfBoundsException;-><init>()V

    throw p0

    :pswitch_0
    if-ltz p2, :cond_1

    .line 13
    array-length p1, p1

    if-gt p2, p1, :cond_1

    if-ltz p3, :cond_1

    add-int/2addr p2, p3

    if-gt p2, p1, :cond_1

    if-ltz p2, :cond_1

    .line 14
    iget-wide p1, p0, Lct/b;->e:J

    int-to-long v0, p3

    add-long/2addr p1, v0

    iput-wide p1, p0, Lct/b;->e:J

    return-void

    .line 15
    :cond_1
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 16
    invoke-direct {p0}, Ljava/lang/IndexOutOfBoundsException;-><init>()V

    throw p0

    :pswitch_1
    if-ltz p2, :cond_2

    .line 17
    array-length p1, p1

    if-gt p2, p1, :cond_2

    if-ltz p3, :cond_2

    add-int/2addr p2, p3

    if-gt p2, p1, :cond_2

    if-ltz p2, :cond_2

    .line 18
    iget-wide p1, p0, Lct/b;->e:J

    int-to-long v0, p3

    add-long/2addr p1, v0

    iput-wide p1, p0, Lct/b;->e:J

    return-void

    .line 19
    :cond_2
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 20
    invoke-direct {p0}, Ljava/lang/IndexOutOfBoundsException;-><init>()V

    throw p0

    :pswitch_2
    if-ltz p2, :cond_3

    .line 21
    array-length v0, p1

    if-gt p2, v0, :cond_3

    if-ltz p3, :cond_3

    add-int/2addr p2, p3

    array-length p1, p1

    if-gt p2, p1, :cond_3

    if-ltz p2, :cond_3

    .line 22
    iget-wide p1, p0, Lct/b;->e:J

    int-to-long v0, p3

    add-long/2addr p1, v0

    iput-wide p1, p0, Lct/b;->e:J

    return-void

    .line 23
    :cond_3
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    invoke-direct {p0}, Ljava/lang/IndexOutOfBoundsException;-><init>()V

    throw p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
