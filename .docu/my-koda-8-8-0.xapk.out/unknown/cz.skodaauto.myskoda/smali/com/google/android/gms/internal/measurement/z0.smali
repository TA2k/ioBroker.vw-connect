.class public final Lcom/google/android/gms/internal/measurement/z0;
.super Lcom/google/android/gms/internal/measurement/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/String;

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:Lcom/google/android/gms/internal/measurement/k1;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/k1;Lcom/google/android/gms/internal/measurement/w0;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lcom/google/android/gms/internal/measurement/z0;->h:I

    .line 1
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/z0;->l:Ljava/lang/Object;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/z0;->i:Ljava/lang/String;

    iput-object p4, p0, Lcom/google/android/gms/internal/measurement/z0;->j:Ljava/lang/String;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/z0;->k:Lcom/google/android/gms/internal/measurement/k1;

    const/4 p2, 0x1

    .line 2
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/android/gms/internal/measurement/z0;->h:I

    .line 3
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/z0;->i:Ljava/lang/String;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/z0;->j:Ljava/lang/String;

    iput-object p4, p0, Lcom/google/android/gms/internal/measurement/z0;->l:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/z0;->k:Lcom/google/android/gms/internal/measurement/k1;

    const/4 p2, 0x1

    .line 4
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Lcom/google/android/gms/internal/measurement/h0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcom/google/android/gms/internal/measurement/z0;->h:I

    .line 5
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/z0;->i:Ljava/lang/String;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/z0;->j:Ljava/lang/String;

    iput-object p4, p0, Lcom/google/android/gms/internal/measurement/z0;->l:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/z0;->k:Lcom/google/android/gms/internal/measurement/k1;

    const/4 p2, 0x1

    .line 6
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 7

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/z0;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/z0;->k:Lcom/google/android/gms/internal/measurement/k1;

    .line 7
    .line 8
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 9
    .line 10
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/z0;->l:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v2, v0

    .line 16
    check-cast v2, Lcom/google/android/gms/internal/measurement/w0;

    .line 17
    .line 18
    iget-object v3, p0, Lcom/google/android/gms/internal/measurement/z0;->i:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v4, p0, Lcom/google/android/gms/internal/measurement/z0;->j:Ljava/lang/String;

    .line 21
    .line 22
    iget-wide v5, p0, Lcom/google/android/gms/internal/measurement/g1;->d:J

    .line 23
    .line 24
    invoke-interface/range {v1 .. v6}, Lcom/google/android/gms/internal/measurement/k0;->setCurrentScreenByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;Ljava/lang/String;Ljava/lang/String;J)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/z0;->k:Lcom/google/android/gms/internal/measurement/k1;

    .line 29
    .line 30
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 31
    .line 32
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/z0;->i:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/z0;->j:Ljava/lang/String;

    .line 38
    .line 39
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/z0;->l:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Lcom/google/android/gms/internal/measurement/h0;

    .line 42
    .line 43
    invoke-interface {v0, v1, v2, p0}, Lcom/google/android/gms/internal/measurement/k0;->getConditionalUserProperties(Ljava/lang/String;Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :pswitch_1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/z0;->k:Lcom/google/android/gms/internal/measurement/k1;

    .line 48
    .line 49
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 50
    .line 51
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/z0;->i:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/z0;->j:Ljava/lang/String;

    .line 57
    .line 58
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/z0;->l:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast p0, Landroid/os/Bundle;

    .line 61
    .line 62
    invoke-interface {v0, v1, v2, p0}, Lcom/google/android/gms/internal/measurement/k0;->clearConditionalUserProperty(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b()V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/z0;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/z0;->l:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lcom/google/android/gms/internal/measurement/h0;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/h0;->I(Landroid/os/Bundle;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
