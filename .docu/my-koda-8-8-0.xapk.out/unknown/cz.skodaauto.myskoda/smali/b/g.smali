.class public final synthetic Lb/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lb/g;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lb/g;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lb/g;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 1

    .line 1
    iget p1, p0, Lb/g;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lb/g;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Ld6/n;

    .line 9
    .line 10
    iget-object p0, p0, Lb/g;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ld6/o;

    .line 13
    .line 14
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    sget-object v0, Landroidx/lifecycle/p;->ON_DESTROY:Landroidx/lifecycle/p;

    .line 18
    .line 19
    if-ne p2, v0, :cond_0

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Ld6/n;->b(Ld6/o;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void

    .line 25
    :pswitch_0
    iget-object p1, p0, Lb/g;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Lb/h0;

    .line 28
    .line 29
    iget-object p0, p0, Lb/g;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Lb/r;

    .line 32
    .line 33
    sget-object v0, Landroidx/lifecycle/p;->ON_CREATE:Landroidx/lifecycle/p;

    .line 34
    .line 35
    if-ne p2, v0, :cond_1

    .line 36
    .line 37
    invoke-static {p0}, Lb/k;->a(Landroid/app/Activity;)Landroid/window/OnBackInvokedDispatcher;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    iput-object p0, p1, Lb/h0;->e:Landroid/window/OnBackInvokedDispatcher;

    .line 42
    .line 43
    iget-boolean p0, p1, Lb/h0;->g:Z

    .line 44
    .line 45
    invoke-virtual {p1, p0}, Lb/h0;->d(Z)V

    .line 46
    .line 47
    .line 48
    :cond_1
    return-void

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
