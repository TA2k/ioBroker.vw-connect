.class public final synthetic Lh70/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh70/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh70/n;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lh70/n;->f:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lh70/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Llj0/b;

    .line 7
    .line 8
    iget-object v1, p0, Lh70/n;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lh70/n;->f:Ljava/lang/String;

    .line 14
    .line 15
    invoke-direct {v0, v1, p0}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    const-string v0, "migrate(): Migrate all pairings from "

    .line 20
    .line 21
    const-string v1, " into "

    .line 22
    .line 23
    iget-object v2, p0, Lh70/n;->e:Ljava/lang/String;

    .line 24
    .line 25
    iget-object p0, p0, Lh70/n;->f:Ljava/lang/String;

    .line 26
    .line 27
    invoke-static {v0, v2, v1, p0}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_1
    const-string v0, " -> "

    .line 33
    .line 34
    const-string v1, " was not found"

    .line 35
    .line 36
    const-string v2, "Text "

    .line 37
    .line 38
    iget-object v3, p0, Lh70/n;->e:Ljava/lang/String;

    .line 39
    .line 40
    iget-object p0, p0, Lh70/n;->f:Ljava/lang/String;

    .line 41
    .line 42
    invoke-static {v2, v3, v0, p0, v1}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
