.class public final synthetic Lh2/l6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Lh2/w5;

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lh2/k6;

.field public final synthetic g:J

.field public final synthetic h:Lt4/m;


# direct methods
.method public synthetic constructor <init>(Lh2/w5;Lay0/a;Lh2/k6;JLt4/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/l6;->d:Lh2/w5;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/l6;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/l6;->f:Lh2/k6;

    .line 9
    .line 10
    iput-wide p4, p0, Lh2/l6;->g:J

    .line 11
    .line 12
    iput-object p6, p0, Lh2/l6;->h:Lt4/m;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-wide v3, p0, Lh2/l6;->g:J

    .line 2
    .line 3
    iget-object v5, p0, Lh2/l6;->h:Lt4/m;

    .line 4
    .line 5
    iget-object v0, p0, Lh2/l6;->d:Lh2/w5;

    .line 6
    .line 7
    iget-object v1, p0, Lh2/l6;->e:Lay0/a;

    .line 8
    .line 9
    iget-object v2, p0, Lh2/l6;->f:Lh2/k6;

    .line 10
    .line 11
    invoke-virtual/range {v0 .. v5}, Lh2/w5;->c(Lay0/a;Lh2/k6;JLt4/m;)V

    .line 12
    .line 13
    .line 14
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    return-object p0
.end method
