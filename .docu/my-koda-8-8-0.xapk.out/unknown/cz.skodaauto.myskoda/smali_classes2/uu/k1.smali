.class public final Luu/k1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luu/s0;


# instance fields
.field public final a:Ll2/r;

.field public final b:Lsp/k;

.field public final c:Luu/l1;

.field public d:Lay0/k;

.field public e:Lay0/k;

.field public f:Lay0/k;

.field public g:Lay0/k;

.field public h:Lay0/o;

.field public i:Lay0/o;


# direct methods
.method public constructor <init>(Ll2/r;Lsp/k;Luu/l1;Lay0/k;Lay0/k;Lay0/k;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "markerState"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onMarkerClick"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "onInfoWindowClick"

    .line 12
    .line 13
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "onInfoWindowClose"

    .line 17
    .line 18
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "onInfoWindowLongClick"

    .line 22
    .line 23
    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Luu/k1;->a:Ll2/r;

    .line 30
    .line 31
    iput-object p2, p0, Luu/k1;->b:Lsp/k;

    .line 32
    .line 33
    iput-object p3, p0, Luu/k1;->c:Luu/l1;

    .line 34
    .line 35
    iput-object p4, p0, Luu/k1;->d:Lay0/k;

    .line 36
    .line 37
    iput-object p5, p0, Luu/k1;->e:Lay0/k;

    .line 38
    .line 39
    iput-object p6, p0, Luu/k1;->f:Lay0/k;

    .line 40
    .line 41
    iput-object p7, p0, Luu/k1;->g:Lay0/k;

    .line 42
    .line 43
    const/4 p1, 0x0

    .line 44
    iput-object p1, p0, Luu/k1;->h:Lay0/o;

    .line 45
    .line 46
    iput-object p1, p0, Luu/k1;->i:Lay0/o;

    .line 47
    .line 48
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 1

    .line 1
    iget-object v0, p0, Luu/k1;->c:Luu/l1;

    .line 2
    .line 3
    iget-object p0, p0, Luu/k1;->b:Lsp/k;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Luu/l1;->b(Lsp/k;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final b()V
    .locals 2

    .line 1
    iget-object v0, p0, Luu/k1;->c:Luu/l1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Luu/l1;->b(Lsp/k;)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Luu/k1;->b:Lsp/k;

    .line 8
    .line 9
    invoke-virtual {p0}, Lsp/k;->c()V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final d()V
    .locals 2

    .line 1
    iget-object v0, p0, Luu/k1;->c:Luu/l1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Luu/l1;->b(Lsp/k;)V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Luu/k1;->b:Lsp/k;

    .line 8
    .line 9
    invoke-virtual {p0}, Lsp/k;->c()V

    .line 10
    .line 11
    .line 12
    return-void
.end method
