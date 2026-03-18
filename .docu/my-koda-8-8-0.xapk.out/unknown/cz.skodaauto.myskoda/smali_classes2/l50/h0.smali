.class public final Ll50/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lj50/k;


# direct methods
.method public constructor <init>(Lj50/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/h0;->a:Lj50/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lm50/b;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ll50/h0;->a:Lj50/k;

    .line 2
    .line 3
    iget-object p0, p0, Lj50/k;->e:Lyy0/c2;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lm50/b;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Ll50/h0;->a(Lm50/b;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method
