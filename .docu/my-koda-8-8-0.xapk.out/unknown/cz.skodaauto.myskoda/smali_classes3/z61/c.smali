.class public final synthetic Lz61/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Z

.field public final synthetic j:Z

.field public final synthetic k:J

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Lay0/a;

.field public final synthetic n:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZZZZZJLay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz61/c;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lz61/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 7
    .line 8
    iput-boolean p3, p0, Lz61/c;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lz61/c;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Lz61/c;->h:Z

    .line 13
    .line 14
    iput-boolean p6, p0, Lz61/c;->i:Z

    .line 15
    .line 16
    iput-boolean p7, p0, Lz61/c;->j:Z

    .line 17
    .line 18
    iput-wide p8, p0, Lz61/c;->k:J

    .line 19
    .line 20
    iput-object p10, p0, Lz61/c;->l:Lay0/a;

    .line 21
    .line 22
    iput-object p11, p0, Lz61/c;->m:Lay0/a;

    .line 23
    .line 24
    iput-object p12, p0, Lz61/c;->n:Lay0/a;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    move-object v12, p1

    .line 2
    check-cast v12, Ll2/o;

    .line 3
    .line 4
    move-object/from16 v0, p2

    .line 5
    .line 6
    check-cast v0, Ljava/lang/Integer;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 13
    .line 14
    .line 15
    move-result v13

    .line 16
    iget-object v0, p0, Lz61/c;->d:Lx2/s;

    .line 17
    .line 18
    iget-object v1, p0, Lz61/c;->e:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 19
    .line 20
    iget-boolean v2, p0, Lz61/c;->f:Z

    .line 21
    .line 22
    iget-boolean v3, p0, Lz61/c;->g:Z

    .line 23
    .line 24
    iget-boolean v4, p0, Lz61/c;->h:Z

    .line 25
    .line 26
    iget-boolean v5, p0, Lz61/c;->i:Z

    .line 27
    .line 28
    iget-boolean v6, p0, Lz61/c;->j:Z

    .line 29
    .line 30
    iget-wide v7, p0, Lz61/c;->k:J

    .line 31
    .line 32
    iget-object v9, p0, Lz61/c;->l:Lay0/a;

    .line 33
    .line 34
    iget-object v10, p0, Lz61/c;->m:Lay0/a;

    .line 35
    .line 36
    iget-object v11, p0, Lz61/c;->n:Lay0/a;

    .line 37
    .line 38
    invoke-static/range {v0 .. v13}, Lz61/h;->d(Lx2/s;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZZZZZJLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 39
    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object p0
.end method
