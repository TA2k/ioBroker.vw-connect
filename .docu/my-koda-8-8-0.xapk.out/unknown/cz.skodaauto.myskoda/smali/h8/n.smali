.class public final synthetic Lh8/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgr/m;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ly7/g;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ly7/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh8/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh8/n;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lh8/n;->f:Ly7/g;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lh8/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh8/n;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lh8/o;

    .line 9
    .line 10
    new-instance v1, Lh8/t0;

    .line 11
    .line 12
    iget-object v0, v0, Lh8/o;->b:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v0, Lo8/m;

    .line 15
    .line 16
    iget-object p0, p0, Lh8/n;->f:Ly7/g;

    .line 17
    .line 18
    invoke-direct {v1, p0, v0}, Lh8/t0;-><init>(Ly7/g;Lo8/r;)V

    .line 19
    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    iget-object v0, p0, Lh8/n;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Ljava/lang/Class;

    .line 25
    .line 26
    iget-object p0, p0, Lh8/n;->f:Ly7/g;

    .line 27
    .line 28
    invoke-static {v0, p0}, Lh8/p;->e(Ljava/lang/Class;Ly7/g;)Lh8/a0;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :pswitch_1
    iget-object v0, p0, Lh8/n;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Ljava/lang/Class;

    .line 36
    .line 37
    iget-object p0, p0, Lh8/n;->f:Ly7/g;

    .line 38
    .line 39
    invoke-static {v0, p0}, Lh8/p;->e(Ljava/lang/Class;Ly7/g;)Lh8/a0;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :pswitch_2
    iget-object v0, p0, Lh8/n;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Ljava/lang/Class;

    .line 47
    .line 48
    iget-object p0, p0, Lh8/n;->f:Ly7/g;

    .line 49
    .line 50
    invoke-static {v0, p0}, Lh8/p;->e(Ljava/lang/Class;Ly7/g;)Lh8/a0;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
