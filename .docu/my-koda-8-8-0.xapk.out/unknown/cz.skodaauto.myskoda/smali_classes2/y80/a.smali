.class public final Ly80/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements La90/q;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lyy0/c2;

.field public final c:Lyy0/l1;

.field public final d:Lez0/c;

.field public e:Ljava/time/LocalDate;

.field public f:Ljava/time/LocalTime;

.field public g:Lb90/s;

.field public h:Lb90/m;

.field public i:Lb90/a;

.field public j:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lwe0/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly80/a;->a:Lwe0/a;

    .line 5
    .line 6
    sget-object p1, Lne0/d;->a:Lne0/d;

    .line 7
    .line 8
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Ly80/a;->b:Lyy0/c2;

    .line 13
    .line 14
    new-instance v0, Lyy0/l1;

    .line 15
    .line 16
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Ly80/a;->c:Lyy0/l1;

    .line 20
    .line 21
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Ly80/a;->d:Lez0/c;

    .line 26
    .line 27
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 28
    .line 29
    iput-object p1, p0, Ly80/a;->j:Ljava/lang/Object;

    .line 30
    .line 31
    return-void
.end method
