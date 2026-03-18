.class public final Ljn/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:Lx2/s;

.field public final synthetic g:Ljn/a;

.field public final synthetic h:Z

.field public final synthetic i:Ljava/lang/Iterable;

.field public final synthetic j:Ljava/lang/Iterable;

.field public final synthetic k:Lay0/n;

.field public final synthetic l:Lay0/k;

.field public final synthetic m:J

.field public final synthetic n:Lg4/p0;


# direct methods
.method public constructor <init>(Lx2/s;Ljn/a;ZLjava/lang/Iterable;Ljava/lang/Iterable;Lay0/n;Lay0/k;JLg4/p0;I)V
    .locals 0

    .line 1
    iput-object p1, p0, Ljn/e;->f:Lx2/s;

    .line 2
    .line 3
    iput-object p2, p0, Ljn/e;->g:Ljn/a;

    .line 4
    .line 5
    iput-boolean p3, p0, Ljn/e;->h:Z

    .line 6
    .line 7
    iput-object p4, p0, Ljn/e;->i:Ljava/lang/Iterable;

    .line 8
    .line 9
    iput-object p5, p0, Ljn/e;->j:Ljava/lang/Iterable;

    .line 10
    .line 11
    iput-object p6, p0, Ljn/e;->k:Lay0/n;

    .line 12
    .line 13
    iput-object p7, p0, Ljn/e;->l:Lay0/k;

    .line 14
    .line 15
    iput-wide p8, p0, Ljn/e;->m:J

    .line 16
    .line 17
    iput-object p10, p0, Ljn/e;->n:Lg4/p0;

    .line 18
    .line 19
    const/4 p1, 0x2

    .line 20
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v10, p1

    .line 2
    check-cast v10, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Number;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 7
    .line 8
    .line 9
    iget-object v9, p0, Ljn/e;->n:Lg4/p0;

    .line 10
    .line 11
    const v11, 0xc30181

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Ljn/e;->f:Lx2/s;

    .line 15
    .line 16
    iget-object v1, p0, Ljn/e;->g:Ljn/a;

    .line 17
    .line 18
    iget-boolean v2, p0, Ljn/e;->h:Z

    .line 19
    .line 20
    iget-object v3, p0, Ljn/e;->i:Ljava/lang/Iterable;

    .line 21
    .line 22
    iget-object v4, p0, Ljn/e;->j:Ljava/lang/Iterable;

    .line 23
    .line 24
    iget-object v5, p0, Ljn/e;->k:Lay0/n;

    .line 25
    .line 26
    iget-object v6, p0, Ljn/e;->l:Lay0/k;

    .line 27
    .line 28
    iget-wide v7, p0, Ljn/e;->m:J

    .line 29
    .line 30
    invoke-static/range {v0 .. v11}, Llp/cc;->c(Lx2/s;Ljn/a;ZLjava/lang/Iterable;Ljava/lang/Iterable;Lay0/n;Lay0/k;JLg4/p0;Ll2/o;I)V

    .line 31
    .line 32
    .line 33
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    return-object p0
.end method
