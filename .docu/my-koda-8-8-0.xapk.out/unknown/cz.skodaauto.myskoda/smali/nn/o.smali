.class public final Lnn/o;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final g:Lnn/o;


# instance fields
.field public final synthetic f:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lnn/o;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lnn/o;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lnn/o;->g:Lnn/o;

    .line 9
    .line 10
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lnn/o;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lnn/o;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/Map;

    .line 7
    .line 8
    const-string p0, "it"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance p0, Lnn/t;

    .line 14
    .line 15
    sget-object v0, Lnn/g;->a:Lnn/g;

    .line 16
    .line 17
    invoke-direct {p0, v0}, Lnn/t;-><init>(Lnn/i;)V

    .line 18
    .line 19
    .line 20
    const-string v0, "pagetitle"

    .line 21
    .line 22
    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Ljava/lang/String;

    .line 27
    .line 28
    iget-object v1, p0, Lnn/t;->d:Ll2/j1;

    .line 29
    .line 30
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    const-string v0, "lastloaded"

    .line 34
    .line 35
    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Ljava/lang/String;

    .line 40
    .line 41
    iget-object v1, p0, Lnn/t;->a:Ll2/j1;

    .line 42
    .line 43
    invoke-virtual {v1, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    const-string v0, "bundle"

    .line 47
    .line 48
    invoke-interface {p1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    check-cast p1, Landroid/os/Bundle;

    .line 53
    .line 54
    iput-object p1, p0, Lnn/t;->g:Landroid/os/Bundle;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_0
    check-cast p1, Landroid/webkit/WebView;

    .line 58
    .line 59
    const-string p0, "it"

    .line 60
    .line 61
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object p0

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
