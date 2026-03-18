.class public final Ldj/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcj/f;


# instance fields
.field public final a:Lcz/j;

.field public final b:Lvy0/b0;

.field public final c:Llx0/q;

.field public final d:Lyy0/l1;

.field public final e:Ldj/i;

.field public final f:Ldj/i;

.field public final g:Lyy0/c2;

.field public final h:Ldj/f;


# direct methods
.method public constructor <init>(Lcz/j;Lvy0/b0;Lrc/b;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldj/g;->a:Lcz/j;

    .line 5
    .line 6
    iput-object p2, p0, Ldj/g;->b:Lvy0/b0;

    .line 7
    .line 8
    new-instance p1, Ldj/b;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-direct {p1, p0, v0}, Ldj/b;-><init>(Ldj/g;I)V

    .line 12
    .line 13
    .line 14
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 15
    .line 16
    .line 17
    new-instance p1, Ldj/b;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, v0}, Ldj/b;-><init>(Ldj/g;I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Ldj/g;->c:Llx0/q;

    .line 28
    .line 29
    iget-object p1, p3, Lrc/b;->b:Lyy0/q1;

    .line 30
    .line 31
    new-instance p3, Lac/l;

    .line 32
    .line 33
    const/16 v0, 0x9

    .line 34
    .line 35
    invoke-direct {p3, v0, p1, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    const-wide/16 v0, 0x0

    .line 39
    .line 40
    const/4 p1, 0x3

    .line 41
    invoke-static {p1, v0, v1}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    sget-object v0, Lri/b;->a:Lri/b;

    .line 46
    .line 47
    invoke-static {p3, p2, p1, v0}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    iput-object p1, p0, Ldj/g;->d:Lyy0/l1;

    .line 52
    .line 53
    sget-object p1, Ldj/i;->a:Ldj/i;

    .line 54
    .line 55
    iput-object p1, p0, Ldj/g;->e:Ldj/i;

    .line 56
    .line 57
    sget-object p1, Ldj/i;->b:Ldj/i;

    .line 58
    .line 59
    iput-object p1, p0, Ldj/g;->f:Ldj/i;

    .line 60
    .line 61
    const/4 p1, 0x0

    .line 62
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iput-object p1, p0, Ldj/g;->g:Lyy0/c2;

    .line 71
    .line 72
    new-instance p1, Ldj/f;

    .line 73
    .line 74
    invoke-direct {p1, p0}, Ldj/f;-><init>(Ldj/g;)V

    .line 75
    .line 76
    .line 77
    iput-object p1, p0, Ldj/g;->h:Ldj/f;

    .line 78
    .line 79
    return-void
.end method
