.class public final Lgb0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lif0/f0;

.field public final b:Len0/s;


# direct methods
.method public constructor <init>(Lif0/f0;Len0/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgb0/m;->a:Lif0/f0;

    .line 5
    .line 6
    iput-object p2, p0, Lgb0/m;->b:Len0/s;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lgb0/m;->a:Lif0/f0;

    .line 2
    .line 3
    iget-object v0, v0, Lif0/f0;->h:Lwe0/a;

    .line 4
    .line 5
    check-cast v0, Lwe0/c;

    .line 6
    .line 7
    invoke-virtual {v0}, Lwe0/c;->a()V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lgb0/m;->b:Len0/s;

    .line 11
    .line 12
    iget-object p0, p0, Len0/s;->f:Lwe0/a;

    .line 13
    .line 14
    check-cast p0, Lwe0/c;

    .line 15
    .line 16
    invoke-virtual {p0}, Lwe0/c;->a()V

    .line 17
    .line 18
    .line 19
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method
