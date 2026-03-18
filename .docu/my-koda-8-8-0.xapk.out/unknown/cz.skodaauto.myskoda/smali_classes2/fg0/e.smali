.class public final Lfg0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lfg0/b;


# direct methods
.method public constructor <init>(Lfg0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfg0/e;->a:Lfg0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lfg0/e;->a:Lfg0/b;

    .line 2
    .line 3
    check-cast p0, Ldg0/a;

    .line 4
    .line 5
    iget-object p0, p0, Ldg0/a;->c:Lyy0/q1;

    .line 6
    .line 7
    sget-object v0, Ldg0/b;->d:Ldg0/b;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method
