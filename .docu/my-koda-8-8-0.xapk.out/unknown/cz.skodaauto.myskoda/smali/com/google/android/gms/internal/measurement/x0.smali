.class public final Lcom/google/android/gms/internal/measurement/x0;
.super Lcom/google/android/gms/internal/measurement/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/String;

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:Z

.field public final synthetic l:Lcom/google/android/gms/internal/measurement/k1;

.field public final synthetic m:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;Z)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lcom/google/android/gms/internal/measurement/x0;->h:I

    .line 1
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/x0;->i:Ljava/lang/String;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/x0;->j:Ljava/lang/String;

    iput-object p4, p0, Lcom/google/android/gms/internal/measurement/x0;->m:Ljava/lang/Object;

    iput-boolean p5, p0, Lcom/google/android/gms/internal/measurement/x0;->k:Z

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/x0;->l:Lcom/google/android/gms/internal/measurement/k1;

    const/4 p2, 0x1

    .line 2
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;Z)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/android/gms/internal/measurement/x0;->h:I

    .line 3
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/x0;->i:Ljava/lang/String;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/x0;->j:Ljava/lang/String;

    iput-object p4, p0, Lcom/google/android/gms/internal/measurement/x0;->m:Ljava/lang/Object;

    iput-boolean p5, p0, Lcom/google/android/gms/internal/measurement/x0;->k:Z

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/x0;->l:Lcom/google/android/gms/internal/measurement/k1;

    const/4 p2, 0x1

    .line 4
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;ZLcom/google/android/gms/internal/measurement/h0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcom/google/android/gms/internal/measurement/x0;->h:I

    .line 5
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/x0;->i:Ljava/lang/String;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/x0;->j:Ljava/lang/String;

    iput-boolean p4, p0, Lcom/google/android/gms/internal/measurement/x0;->k:Z

    iput-object p5, p0, Lcom/google/android/gms/internal/measurement/x0;->m:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/x0;->l:Lcom/google/android/gms/internal/measurement/k1;

    const/4 p2, 0x1

    .line 6
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 9

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/x0;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-wide v7, p0, Lcom/google/android/gms/internal/measurement/g1;->d:J

    .line 7
    .line 8
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/x0;->l:Lcom/google/android/gms/internal/measurement/k1;

    .line 9
    .line 10
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 11
    .line 12
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/x0;->i:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v3, p0, Lcom/google/android/gms/internal/measurement/x0;->j:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/x0;->m:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v4, v0

    .line 22
    check-cast v4, Landroid/os/Bundle;

    .line 23
    .line 24
    iget-boolean v5, p0, Lcom/google/android/gms/internal/measurement/x0;->k:Z

    .line 25
    .line 26
    const/4 v6, 0x1

    .line 27
    invoke-interface/range {v1 .. v8}, Lcom/google/android/gms/internal/measurement/k0;->logEvent(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;ZZJ)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :pswitch_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/x0;->l:Lcom/google/android/gms/internal/measurement/k1;

    .line 32
    .line 33
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 34
    .line 35
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/x0;->i:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/x0;->j:Ljava/lang/String;

    .line 41
    .line 42
    iget-boolean v3, p0, Lcom/google/android/gms/internal/measurement/x0;->k:Z

    .line 43
    .line 44
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/x0;->m:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Lcom/google/android/gms/internal/measurement/h0;

    .line 47
    .line 48
    invoke-interface {v0, v1, v2, v3, p0}, Lcom/google/android/gms/internal/measurement/k0;->getUserProperties(Ljava/lang/String;Ljava/lang/String;ZLcom/google/android/gms/internal/measurement/m0;)V

    .line 49
    .line 50
    .line 51
    return-void

    .line 52
    :pswitch_1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/x0;->l:Lcom/google/android/gms/internal/measurement/k1;

    .line 53
    .line 54
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 55
    .line 56
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/x0;->m:Ljava/lang/Object;

    .line 60
    .line 61
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/x0;->i:Ljava/lang/String;

    .line 62
    .line 63
    iget-object v3, p0, Lcom/google/android/gms/internal/measurement/x0;->j:Ljava/lang/String;

    .line 64
    .line 65
    new-instance v4, Lyo/b;

    .line 66
    .line 67
    invoke-direct {v4, v0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iget-boolean v5, p0, Lcom/google/android/gms/internal/measurement/x0;->k:Z

    .line 71
    .line 72
    iget-wide v6, p0, Lcom/google/android/gms/internal/measurement/g1;->d:J

    .line 73
    .line 74
    invoke-interface/range {v1 .. v7}, Lcom/google/android/gms/internal/measurement/k0;->setUserProperty(Ljava/lang/String;Ljava/lang/String;Lyo/a;ZJ)V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b()V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/x0;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/x0;->m:Ljava/lang/Object;

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
