.class public final Lxw/g;
.super Lcom/google/android/gms/internal/measurement/i4;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:I

.field public final synthetic l:Lcom/google/android/gms/internal/measurement/i4;


# direct methods
.method public synthetic constructor <init>(Lxw/h;Ljava/lang/String;ILcom/google/android/gms/internal/measurement/i4;I)V
    .locals 0

    .line 1
    iput p5, p0, Lxw/g;->i:I

    .line 2
    .line 3
    iput-object p2, p0, Lxw/g;->j:Ljava/lang/String;

    .line 4
    .line 5
    iput p3, p0, Lxw/g;->k:I

    .line 6
    .line 7
    iput-object p4, p0, Lxw/g;->l:Lcom/google/android/gms/internal/measurement/i4;

    .line 8
    .line 9
    const/4 p2, 0x0

    .line 10
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/i4;-><init>(Lxw/h;Z)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final c(ILjava/lang/String;)Lcom/google/android/gms/internal/measurement/i4;
    .locals 8

    .line 1
    iget v0, p0, Lxw/g;->i:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxw/g;->j:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, p1, p2}, Lcom/google/android/gms/internal/measurement/i4;->v(Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, Lxw/g;->l:Lcom/google/android/gms/internal/measurement/i4;

    .line 12
    .line 13
    iget-object v0, p1, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Ljava/util/ArrayList;

    .line 16
    .line 17
    new-instance v1, Lxw/m;

    .line 18
    .line 19
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v2, Lxw/h;

    .line 22
    .line 23
    invoke-super {p0}, Lcom/google/android/gms/internal/measurement/i4;->q()[Lxw/u;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    iget v5, p0, Lxw/g;->k:I

    .line 28
    .line 29
    const/4 v6, 0x0

    .line 30
    move-object v3, p2

    .line 31
    invoke-direct/range {v1 .. v6}, Lxw/m;-><init>(Lxw/h;Ljava/lang/String;[Lxw/u;II)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    return-object p1

    .line 38
    :pswitch_0
    move-object v3, p2

    .line 39
    iget-object p2, p0, Lxw/g;->j:Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {p2, p1, v3}, Lcom/google/android/gms/internal/measurement/i4;->v(Ljava/lang/String;ILjava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lxw/g;->l:Lcom/google/android/gms/internal/measurement/i4;

    .line 45
    .line 46
    iget-object p2, p1, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p2, Ljava/util/ArrayList;

    .line 49
    .line 50
    new-instance v2, Lxw/m;

    .line 51
    .line 52
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Lxw/h;

    .line 55
    .line 56
    invoke-super {p0}, Lcom/google/android/gms/internal/measurement/i4;->q()[Lxw/u;

    .line 57
    .line 58
    .line 59
    move-result-object v5

    .line 60
    iget v6, p0, Lxw/g;->k:I

    .line 61
    .line 62
    const/4 v7, 0x1

    .line 63
    move-object v4, v3

    .line 64
    move-object v3, v0

    .line 65
    invoke-direct/range {v2 .. v7}, Lxw/m;-><init>(Lxw/h;Ljava/lang/String;[Lxw/u;II)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    return-object p1

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final q()[Lxw/u;
    .locals 4

    .line 1
    iget v0, p0, Lxw/g;->i:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lxw/r;

    .line 7
    .line 8
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v2, "Inverted section missing close tag \'"

    .line 11
    .line 12
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object v2, p0, Lxw/g;->j:Ljava/lang/String;

    .line 16
    .line 17
    const-string v3, "\'"

    .line 18
    .line 19
    invoke-static {v1, v2, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    iget p0, p0, Lxw/g;->k:I

    .line 24
    .line 25
    invoke-direct {v0, v1, p0}, Lxw/r;-><init>(Ljava/lang/String;I)V

    .line 26
    .line 27
    .line 28
    throw v0

    .line 29
    :pswitch_0
    new-instance v0, Lxw/r;

    .line 30
    .line 31
    new-instance v1, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v2, "Section missing close tag \'"

    .line 34
    .line 35
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object v2, p0, Lxw/g;->j:Ljava/lang/String;

    .line 39
    .line 40
    const-string v3, "\'"

    .line 41
    .line 42
    invoke-static {v1, v2, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    iget p0, p0, Lxw/g;->k:I

    .line 47
    .line 48
    invoke-direct {v0, v1, p0}, Lxw/r;-><init>(Ljava/lang/String;I)V

    .line 49
    .line 50
    .line 51
    throw v0

    .line 52
    nop

    .line 53
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
