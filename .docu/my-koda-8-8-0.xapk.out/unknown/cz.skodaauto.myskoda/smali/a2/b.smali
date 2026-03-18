.class public final La2/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw1/g;


# instance fields
.field public final a:La2/k;

.field public final b:Lxy0/j;


# direct methods
.method public constructor <init>(La2/k;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La2/b;->a:La2/k;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    const/4 v0, 0x7

    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-static {v1, v0, p1}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iput-object p1, p0, La2/b;->b:Lxy0/j;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 1

    .line 1
    iget-object p0, p0, La2/b;->b:Lxy0/j;

    .line 2
    .line 3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    invoke-interface {p0, v0}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method
