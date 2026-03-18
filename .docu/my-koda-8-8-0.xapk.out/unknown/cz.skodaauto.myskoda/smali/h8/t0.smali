.class public final Lh8/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh8/a0;


# instance fields
.field public final a:Ly7/g;

.field public final b:Lgr/k;

.field public final c:Ld8/c;

.field public final d:Lmb/e;

.field public final e:I


# direct methods
.method public constructor <init>(Ly7/g;Lo8/r;)V
    .locals 3

    .line 1
    new-instance v0, Lgr/k;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, p2, v1}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    new-instance p2, Ld8/c;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-direct {p2, v1}, Ld8/c;-><init>(I)V

    .line 11
    .line 12
    .line 13
    new-instance v1, Lmb/e;

    .line 14
    .line 15
    const/16 v2, 0x8

    .line 16
    .line 17
    invoke-direct {v1, v2}, Lmb/e;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Lh8/t0;->a:Ly7/g;

    .line 24
    .line 25
    iput-object v0, p0, Lh8/t0;->b:Lgr/k;

    .line 26
    .line 27
    iput-object p2, p0, Lh8/t0;->c:Ld8/c;

    .line 28
    .line 29
    iput-object v1, p0, Lh8/t0;->d:Lmb/e;

    .line 30
    .line 31
    const/high16 p1, 0x100000

    .line 32
    .line 33
    iput p1, p0, Lh8/t0;->e:I

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final b(Lt7/x;)Lh8/a;
    .locals 9

    .line 1
    iget-object v0, p1, Lt7/x;->b:Lt7/u;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    new-instance v1, Lh8/u0;

    .line 7
    .line 8
    iget-object v0, p0, Lh8/t0;->c:Ld8/c;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget-object v0, p1, Lt7/x;->b:Lt7/u;

    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    iget-object v0, p1, Lt7/x;->b:Lt7/u;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    iget v7, p0, Lh8/t0;->e:I

    .line 24
    .line 25
    const/4 v8, 0x0

    .line 26
    iget-object v3, p0, Lh8/t0;->a:Ly7/g;

    .line 27
    .line 28
    iget-object v4, p0, Lh8/t0;->b:Lgr/k;

    .line 29
    .line 30
    sget-object v5, Ld8/j;->a:Ld8/h;

    .line 31
    .line 32
    iget-object v6, p0, Lh8/t0;->d:Lmb/e;

    .line 33
    .line 34
    move-object v2, p1

    .line 35
    invoke-direct/range {v1 .. v8}, Lh8/u0;-><init>(Lt7/x;Ly7/g;Lgr/k;Ld8/j;Lmb/e;ILt7/o;)V

    .line 36
    .line 37
    .line 38
    return-object v1
.end method
