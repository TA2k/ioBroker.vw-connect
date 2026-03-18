.class public final Lk1/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk1/g;
.implements Lk1/i;


# instance fields
.field public final synthetic d:I

.field public e:F


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lk1/f;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    int-to-float p1, p1

    .line 11
    iput p1, p0, Lk1/f;->e:F

    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    const/4 p1, 0x0

    .line 22
    int-to-float p1, p1

    .line 23
    iput p1, p0, Lk1/f;->e:F

    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    int-to-float p1, p1

    .line 31
    iput p1, p0, Lk1/f;->e:F

    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 35
    .line 36
    .line 37
    const/4 p1, 0x0

    .line 38
    int-to-float p1, p1

    .line 39
    iput p1, p0, Lk1/f;->e:F

    .line 40
    .line 41
    return-void

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public a()F
    .locals 1

    .line 1
    iget v0, p0, Lk1/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p0, Lk1/f;->e:F

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    iget p0, p0, Lk1/f;->e:F

    .line 10
    .line 11
    return p0

    .line 12
    :pswitch_1
    iget p0, p0, Lk1/f;->e:F

    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_2
    iget p0, p0, Lk1/f;->e:F

    .line 16
    .line 17
    return p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b(Lt4/c;I[I[I)V
    .locals 0

    .line 1
    iget p0, p0, Lk1/f;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    invoke-static {p2, p3, p4, p0}, Lk1/j;->f(I[I[IZ)V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :pswitch_0
    const/4 p0, 0x0

    .line 12
    invoke-static {p2, p3, p4, p0}, Lk1/j;->e(I[I[IZ)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_1
    const/4 p0, 0x0

    .line 17
    invoke-static {p2, p3, p4, p0}, Lk1/j;->d(I[I[IZ)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_2
    const/4 p0, 0x0

    .line 22
    invoke-static {p2, p3, p4, p0}, Lk1/j;->a(I[I[IZ)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public c(Lt4/c;I[ILt4/m;[I)V
    .locals 0

    .line 1
    iget p0, p0, Lk1/f;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lt4/m;->d:Lt4/m;

    .line 7
    .line 8
    if-ne p4, p0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    invoke-static {p2, p3, p5, p0}, Lk1/j;->f(I[I[IZ)V

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 p0, 0x1

    .line 16
    invoke-static {p2, p3, p5, p0}, Lk1/j;->f(I[I[IZ)V

    .line 17
    .line 18
    .line 19
    :goto_0
    return-void

    .line 20
    :pswitch_0
    sget-object p0, Lt4/m;->d:Lt4/m;

    .line 21
    .line 22
    if-ne p4, p0, :cond_1

    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    invoke-static {p2, p3, p5, p0}, Lk1/j;->e(I[I[IZ)V

    .line 26
    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const/4 p0, 0x1

    .line 30
    invoke-static {p2, p3, p5, p0}, Lk1/j;->e(I[I[IZ)V

    .line 31
    .line 32
    .line 33
    :goto_1
    return-void

    .line 34
    :pswitch_1
    sget-object p0, Lt4/m;->d:Lt4/m;

    .line 35
    .line 36
    if-ne p4, p0, :cond_2

    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    invoke-static {p2, p3, p5, p0}, Lk1/j;->d(I[I[IZ)V

    .line 40
    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_2
    const/4 p0, 0x1

    .line 44
    invoke-static {p2, p3, p5, p0}, Lk1/j;->d(I[I[IZ)V

    .line 45
    .line 46
    .line 47
    :goto_2
    return-void

    .line 48
    :pswitch_2
    sget-object p0, Lt4/m;->d:Lt4/m;

    .line 49
    .line 50
    if-ne p4, p0, :cond_3

    .line 51
    .line 52
    const/4 p0, 0x0

    .line 53
    invoke-static {p2, p3, p5, p0}, Lk1/j;->a(I[I[IZ)V

    .line 54
    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_3
    const/4 p0, 0x1

    .line 58
    invoke-static {p2, p3, p5, p0}, Lk1/j;->a(I[I[IZ)V

    .line 59
    .line 60
    .line 61
    :goto_3
    return-void

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lk1/f;->d:I

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
    const-string p0, "Arrangement#SpaceEvenly"

    .line 12
    .line 13
    return-object p0

    .line 14
    :pswitch_1
    const-string p0, "Arrangement#SpaceBetween"

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_2
    const-string p0, "Arrangement#SpaceAround"

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_3
    const-string p0, "Arrangement#Center"

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
