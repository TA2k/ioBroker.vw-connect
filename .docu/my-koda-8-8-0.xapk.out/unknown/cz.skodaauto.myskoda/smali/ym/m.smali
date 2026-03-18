.class public final Lym/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/t2;


# instance fields
.field public final d:Lvy0/r;

.field public final e:Ll2/j1;

.field public final f:Ll2/j1;

.field public final g:Ll2/h0;

.field public final h:Ll2/h0;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lvy0/e0;->b()Lvy0/r;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lym/m;->d:Lvy0/r;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iput-object v1, p0, Lym/m;->e:Ll2/j1;

    .line 16
    .line 17
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iput-object v0, p0, Lym/m;->f:Ll2/j1;

    .line 22
    .line 23
    new-instance v0, Lym/l;

    .line 24
    .line 25
    const/4 v1, 0x2

    .line 26
    invoke-direct {v0, p0, v1}, Lym/l;-><init>(Lym/m;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {v0}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 30
    .line 31
    .line 32
    new-instance v0, Lym/l;

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    invoke-direct {v0, p0, v1}, Lym/l;-><init>(Lym/m;I)V

    .line 36
    .line 37
    .line 38
    invoke-static {v0}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    iput-object v0, p0, Lym/m;->g:Ll2/h0;

    .line 43
    .line 44
    new-instance v0, Lym/l;

    .line 45
    .line 46
    const/4 v1, 0x1

    .line 47
    invoke-direct {v0, p0, v1}, Lym/l;-><init>(Lym/m;I)V

    .line 48
    .line 49
    .line 50
    invoke-static {v0}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 51
    .line 52
    .line 53
    new-instance v0, Lym/l;

    .line 54
    .line 55
    const/4 v1, 0x3

    .line 56
    invoke-direct {v0, p0, v1}, Lym/l;-><init>(Lym/m;I)V

    .line 57
    .line 58
    .line 59
    invoke-static {v0}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    iput-object v0, p0, Lym/m;->h:Ll2/h0;

    .line 64
    .line 65
    return-void
.end method


# virtual methods
.method public final getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lym/m;->e:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lum/a;

    .line 8
    .line 9
    return-object p0
.end method
