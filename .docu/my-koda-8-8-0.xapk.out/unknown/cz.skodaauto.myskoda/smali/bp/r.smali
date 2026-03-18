.class public final Lbp/r;
.super Llo/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Laq/k;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Laq/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbp/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbp/r;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lbp/r;->e:Laq/k;

    .line 6
    .line 7
    invoke-direct {p0}, Llo/h;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final A(Lcom/google/android/gms/common/api/Status;)V
    .locals 2

    .line 1
    iget v0, p0, Lbp/r;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lbp/r;->f:Ljava/lang/Object;

    .line 7
    .line 8
    iget-object p0, p0, Lbp/r;->e:Laq/k;

    .line 9
    .line 10
    invoke-static {p1, v0, p0}, Llp/yf;->b(Lcom/google/android/gms/common/api/Status;Ljava/lang/Object;Laq/k;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object v0, p0, Lbp/r;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lbp/s;

    .line 17
    .line 18
    iget-object v0, v0, Lbp/s;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Lbp/t;

    .line 21
    .line 22
    iget-object p0, p0, Lbp/r;->e:Laq/k;

    .line 23
    .line 24
    iget-object p0, p0, Laq/k;->a:Laq/t;

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    invoke-virtual {p0, v1}, Laq/t;->q(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    invoke-virtual {p1}, Lcom/google/android/gms/common/api/Status;->x0()Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-eqz p0, :cond_0

    .line 38
    .line 39
    iget-object p0, v0, Lbp/t;->b:Laq/k;

    .line 40
    .line 41
    invoke-virtual {p0, v1}, Laq/k;->b(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    iget-object p0, v0, Lbp/t;->b:Laq/k;

    .line 46
    .line 47
    const-string v0, "Indexing error, please try again."

    .line 48
    .line 49
    invoke-static {p1, v0}, Lbp/m;->a(Lcom/google/android/gms/common/api/Status;Ljava/lang/String;)Lb0/l;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    invoke-virtual {p0, p1}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 54
    .line 55
    .line 56
    :cond_1
    :goto_0
    return-void

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
