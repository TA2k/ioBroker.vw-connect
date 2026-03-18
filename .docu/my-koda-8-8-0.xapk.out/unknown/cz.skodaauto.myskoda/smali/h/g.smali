.class public final Lh/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lra/c;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lh/g;->a:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh/g;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lra/d;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lh/g;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    iput-object v0, p0, Lh/g;->b:Ljava/lang/Object;

    .line 3
    const-string v0, "androidx.savedstate.Restarter"

    invoke-virtual {p1, v0, p0}, Lra/d;->c(Ljava/lang/String;Lra/c;)V

    return-void
.end method


# virtual methods
.method public final a()Landroid/os/Bundle;
    .locals 2

    .line 1
    iget v0, p0, Lh/g;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    new-array v1, v0, [Llx0/l;

    .line 8
    .line 9
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, [Llx0/l;

    .line 14
    .line 15
    invoke-static {v0}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iget-object p0, p0, Lh/g;->b:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Ljava/util/LinkedHashSet;

    .line 22
    .line 23
    invoke-static {p0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const-string v1, "classes_to_restore"

    .line 28
    .line 29
    invoke-static {v0, v1, p0}, Lkp/v;->g(Landroid/os/Bundle;Ljava/lang/String;Ljava/util/List;)V

    .line 30
    .line 31
    .line 32
    return-object v0

    .line 33
    :pswitch_0
    new-instance v0, Landroid/os/Bundle;

    .line 34
    .line 35
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lh/g;->b:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 41
    .line 42
    invoke-virtual {p0}, Lh/i;->i()Lh/n;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    return-object v0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
