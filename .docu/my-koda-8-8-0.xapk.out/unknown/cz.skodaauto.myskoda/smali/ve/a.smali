.class public final synthetic Lve/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ll2/b1;

.field public final synthetic h:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Ll2/b1;Lay0/a;I)V
    .locals 0

    .line 1
    iput p5, p0, Lve/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lve/a;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lve/a;->f:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Lve/a;->g:Ll2/b1;

    .line 8
    .line 9
    iput-object p4, p0, Lve/a;->h:Lay0/a;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lve/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lz9/w;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$navigation"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lo50/p;

    .line 14
    .line 15
    iget-object v1, p0, Lve/a;->e:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v2, p0, Lve/a;->f:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v3, p0, Lve/a;->g:Ll2/b1;

    .line 20
    .line 21
    iget-object p0, p0, Lve/a;->h:Lay0/a;

    .line 22
    .line 23
    invoke-direct {v0, v1, v2, v3, p0}, Lo50/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ll2/b1;Lay0/a;)V

    .line 24
    .line 25
    .line 26
    new-instance p0, Lt2/b;

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    const v2, 0x7e430b87

    .line 30
    .line 31
    .line 32
    invoke-direct {p0, v0, v1, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 33
    .line 34
    .line 35
    const-string v0, "FIXED_RATE_ENTER_PRICE"

    .line 36
    .line 37
    invoke-static {p1, v0, p0}, Ljp/jf;->a(Lz9/w;Ljava/lang/String;Lt2/b;)V

    .line 38
    .line 39
    .line 40
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_0
    const-string v0, "<this>"

    .line 44
    .line 45
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    new-instance v1, Lve/a;

    .line 49
    .line 50
    const/4 v6, 0x1

    .line 51
    iget-object v2, p0, Lve/a;->e:Ljava/lang/String;

    .line 52
    .line 53
    iget-object v3, p0, Lve/a;->f:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v4, p0, Lve/a;->g:Ll2/b1;

    .line 56
    .line 57
    iget-object v5, p0, Lve/a;->h:Lay0/a;

    .line 58
    .line 59
    invoke-direct/range {v1 .. v6}, Lve/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ll2/b1;Lay0/a;I)V

    .line 60
    .line 61
    .line 62
    const-string p0, "FIXED_RATE_ENTER_PRICE"

    .line 63
    .line 64
    const-string v0, "FIXED_RATE_GRAPH"

    .line 65
    .line 66
    invoke-static {p1, p0, v0, v1}, Ljp/r0;->e(Lz9/w;Ljava/lang/String;Ljava/lang/String;Lay0/k;)V

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
