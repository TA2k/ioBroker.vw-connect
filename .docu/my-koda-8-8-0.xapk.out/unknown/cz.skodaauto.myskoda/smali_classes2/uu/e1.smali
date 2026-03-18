.class public final Luu/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ll2/j1;

.field public final b:Ll2/j1;

.field public final c:Ll2/j1;

.field public final d:Ll2/j1;

.field public final e:Ll2/j1;

.field public final f:Ll2/j1;

.field public final g:Ll2/j1;

.field public final h:Ll2/j1;


# direct methods
.method public constructor <init>(Luu/g;Lk1/z0;Luu/u0;Luu/a1;Ljava/lang/Integer;)V
    .locals 2

    .line 1
    const-string v0, "cameraPositionState"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "contentPadding"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "mapProperties"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "mapUiSettings"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 25
    .line 26
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iput-object v0, p0, Luu/e1;->a:Ll2/j1;

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    iput-object v1, p0, Luu/e1;->b:Ll2/j1;

    .line 38
    .line 39
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    iput-object p1, p0, Luu/e1;->c:Ll2/j1;

    .line 44
    .line 45
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    iput-object p1, p0, Luu/e1;->d:Ll2/j1;

    .line 50
    .line 51
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    iput-object p1, p0, Luu/e1;->e:Ll2/j1;

    .line 56
    .line 57
    invoke-static {p3}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    iput-object p1, p0, Luu/e1;->f:Ll2/j1;

    .line 62
    .line 63
    invoke-static {p4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    iput-object p1, p0, Luu/e1;->g:Ll2/j1;

    .line 68
    .line 69
    invoke-static {p5}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    iput-object p1, p0, Luu/e1;->h:Ll2/j1;

    .line 74
    .line 75
    return-void
.end method


# virtual methods
.method public final a()Luu/u0;
    .locals 0

    .line 1
    iget-object p0, p0, Luu/e1;->f:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Luu/u0;

    .line 8
    .line 9
    return-object p0
.end method

.method public final b()Luu/a1;
    .locals 0

    .line 1
    iget-object p0, p0, Luu/e1;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Luu/a1;

    .line 8
    .line 9
    return-object p0
.end method
