.class public final Lf01/h;
.super Lu01/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public f:Z

.field public final g:Lay0/k;


# direct methods
.method public constructor <init>(Lu01/f0;La3/f;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lf01/h;->e:I

    .line 1
    invoke-direct {p0, p1}, Lu01/m;-><init>(Lu01/f0;)V

    .line 2
    iput-object p2, p0, Lf01/h;->g:Lay0/k;

    return-void
.end method

.method public constructor <init>(Lu01/f0;Lay0/k;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lf01/h;->e:I

    const-string v0, "delegate"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-direct {p0, p1}, Lu01/m;-><init>(Lu01/f0;)V

    .line 4
    iput-object p2, p0, Lf01/h;->g:Lay0/k;

    return-void
.end method


# virtual methods
.method public final F(Lu01/f;J)V
    .locals 1

    .line 1
    iget v0, p0, Lf01/h;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lf01/h;->f:Z

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p1, p2, p3}, Lu01/f;->skip(J)V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    :try_start_0
    invoke-super {p0, p1, p2, p3}, Lu01/m;->F(Lu01/f;J)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catch_0
    move-exception p1

    .line 19
    const/4 p2, 0x1

    .line 20
    iput-boolean p2, p0, Lf01/h;->f:Z

    .line 21
    .line 22
    iget-object p0, p0, Lf01/h;->g:Lay0/k;

    .line 23
    .line 24
    check-cast p0, La3/f;

    .line 25
    .line 26
    invoke-virtual {p0, p1}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    :goto_0
    return-void

    .line 30
    :pswitch_0
    const-string v0, "source"

    .line 31
    .line 32
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-boolean v0, p0, Lf01/h;->f:Z

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    invoke-virtual {p1, p2, p3}, Lu01/f;->skip(J)V

    .line 40
    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    :try_start_1
    invoke-super {p0, p1, p2, p3}, Lu01/m;->F(Lu01/f;J)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :catch_1
    move-exception p1

    .line 48
    const/4 p2, 0x1

    .line 49
    iput-boolean p2, p0, Lf01/h;->f:Z

    .line 50
    .line 51
    iget-object p0, p0, Lf01/h;->g:Lay0/k;

    .line 52
    .line 53
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    :goto_1
    return-void

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final close()V
    .locals 2

    .line 1
    iget v0, p0, Lf01/h;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-super {p0}, Lu01/m;->close()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 7
    .line 8
    .line 9
    goto :goto_0

    .line 10
    :catch_0
    move-exception v0

    .line 11
    const/4 v1, 0x1

    .line 12
    iput-boolean v1, p0, Lf01/h;->f:Z

    .line 13
    .line 14
    iget-object p0, p0, Lf01/h;->g:Lay0/k;

    .line 15
    .line 16
    check-cast p0, La3/f;

    .line 17
    .line 18
    invoke-virtual {p0, v0}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    :goto_0
    return-void

    .line 22
    :pswitch_0
    :try_start_1
    invoke-super {p0}, Lu01/m;->close()V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 23
    .line 24
    .line 25
    goto :goto_1

    .line 26
    :catch_1
    move-exception v0

    .line 27
    const/4 v1, 0x1

    .line 28
    iput-boolean v1, p0, Lf01/h;->f:Z

    .line 29
    .line 30
    iget-object p0, p0, Lf01/h;->g:Lay0/k;

    .line 31
    .line 32
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    :goto_1
    return-void

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final flush()V
    .locals 2

    .line 1
    iget v0, p0, Lf01/h;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-super {p0}, Lu01/m;->flush()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 7
    .line 8
    .line 9
    goto :goto_0

    .line 10
    :catch_0
    move-exception v0

    .line 11
    const/4 v1, 0x1

    .line 12
    iput-boolean v1, p0, Lf01/h;->f:Z

    .line 13
    .line 14
    iget-object p0, p0, Lf01/h;->g:Lay0/k;

    .line 15
    .line 16
    check-cast p0, La3/f;

    .line 17
    .line 18
    invoke-virtual {p0, v0}, La3/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    :goto_0
    return-void

    .line 22
    :pswitch_0
    iget-boolean v0, p0, Lf01/h;->f:Z

    .line 23
    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_0
    :try_start_1
    invoke-super {p0}, Lu01/m;->flush()V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 28
    .line 29
    .line 30
    goto :goto_1

    .line 31
    :catch_1
    move-exception v0

    .line 32
    const/4 v1, 0x1

    .line 33
    iput-boolean v1, p0, Lf01/h;->f:Z

    .line 34
    .line 35
    iget-object p0, p0, Lf01/h;->g:Lay0/k;

    .line 36
    .line 37
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    :goto_1
    return-void

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
