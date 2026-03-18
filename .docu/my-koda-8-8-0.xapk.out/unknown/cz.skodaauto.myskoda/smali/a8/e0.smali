.class public final synthetic La8/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt7/a1;


# direct methods
.method public synthetic constructor <init>(Lb8/a;Lt7/a1;)V
    .locals 0

    .line 1
    const/4 p1, 0x1

    iput p1, p0, La8/e0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, La8/e0;->e:Lt7/a1;

    return-void
.end method

.method public synthetic constructor <init>(Lt7/a1;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, La8/e0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/e0;->e:Lt7/a1;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget v0, p0, La8/e0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lb8/j;

    .line 7
    .line 8
    iget-object v0, p1, Lb8/j;->p:Lb81/a;

    .line 9
    .line 10
    iget-object p0, p0, La8/e0;->e:Lt7/a1;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    iget-object v1, v0, Lb81/a;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lt7/o;

    .line 17
    .line 18
    iget v2, v1, Lt7/o;->v:I

    .line 19
    .line 20
    const/4 v3, -0x1

    .line 21
    if-ne v2, v3, :cond_0

    .line 22
    .line 23
    invoke-virtual {v1}, Lt7/o;->a()Lt7/n;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    iget v2, p0, Lt7/a1;->a:I

    .line 28
    .line 29
    iput v2, v1, Lt7/n;->t:I

    .line 30
    .line 31
    iget v2, p0, Lt7/a1;->b:I

    .line 32
    .line 33
    iput v2, v1, Lt7/n;->u:I

    .line 34
    .line 35
    new-instance v2, Lt7/o;

    .line 36
    .line 37
    invoke-direct {v2, v1}, Lt7/o;-><init>(Lt7/n;)V

    .line 38
    .line 39
    .line 40
    new-instance v1, Lb81/a;

    .line 41
    .line 42
    iget-object v0, v0, Lb81/a;->f:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v0, Ljava/lang/String;

    .line 45
    .line 46
    const/4 v3, 0x2

    .line 47
    invoke-direct {v1, v3, v2, v0}, Lb81/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    iput-object v1, p1, Lb8/j;->p:Lb81/a;

    .line 51
    .line 52
    :cond_0
    iget p0, p0, Lt7/a1;->a:I

    .line 53
    .line 54
    return-void

    .line 55
    :pswitch_0
    iget-object p0, p0, La8/e0;->e:Lt7/a1;

    .line 56
    .line 57
    check-cast p1, Lt7/j0;

    .line 58
    .line 59
    invoke-interface {p1, p0}, Lt7/j0;->a(Lt7/a1;)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
