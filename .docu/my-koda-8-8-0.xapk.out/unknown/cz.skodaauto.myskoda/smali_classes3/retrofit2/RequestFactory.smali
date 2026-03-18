.class final Lretrofit2/RequestFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lretrofit2/RequestFactory$Builder;
    }
.end annotation


# instance fields
.field public final a:Ljava/lang/Class;

.field public final b:Ljava/lang/reflect/Method;

.field public final c:Ld01/a0;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ld01/y;

.field public final g:Ld01/d0;

.field public final h:Z

.field public final i:Z

.field public final j:Z

.field public final k:[Lretrofit2/ParameterHandler;

.field public final l:Z


# direct methods
.method public constructor <init>(Lretrofit2/RequestFactory$Builder;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lretrofit2/RequestFactory$Builder;->b:Ljava/lang/Class;

    .line 5
    .line 6
    iput-object v0, p0, Lretrofit2/RequestFactory;->a:Ljava/lang/Class;

    .line 7
    .line 8
    iget-object v0, p1, Lretrofit2/RequestFactory$Builder;->c:Ljava/lang/reflect/Method;

    .line 9
    .line 10
    iput-object v0, p0, Lretrofit2/RequestFactory;->b:Ljava/lang/reflect/Method;

    .line 11
    .line 12
    iget-object v0, p1, Lretrofit2/RequestFactory$Builder;->a:Lretrofit2/Retrofit;

    .line 13
    .line 14
    iget-object v0, v0, Lretrofit2/Retrofit;->c:Ld01/a0;

    .line 15
    .line 16
    iput-object v0, p0, Lretrofit2/RequestFactory;->c:Ld01/a0;

    .line 17
    .line 18
    iget-object v0, p1, Lretrofit2/RequestFactory$Builder;->o:Ljava/lang/String;

    .line 19
    .line 20
    iput-object v0, p0, Lretrofit2/RequestFactory;->d:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v0, p1, Lretrofit2/RequestFactory$Builder;->s:Ljava/lang/String;

    .line 23
    .line 24
    iput-object v0, p0, Lretrofit2/RequestFactory;->e:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v0, p1, Lretrofit2/RequestFactory$Builder;->t:Ld01/y;

    .line 27
    .line 28
    iput-object v0, p0, Lretrofit2/RequestFactory;->f:Ld01/y;

    .line 29
    .line 30
    iget-object v0, p1, Lretrofit2/RequestFactory$Builder;->u:Ld01/d0;

    .line 31
    .line 32
    iput-object v0, p0, Lretrofit2/RequestFactory;->g:Ld01/d0;

    .line 33
    .line 34
    iget-boolean v0, p1, Lretrofit2/RequestFactory$Builder;->p:Z

    .line 35
    .line 36
    iput-boolean v0, p0, Lretrofit2/RequestFactory;->h:Z

    .line 37
    .line 38
    iget-boolean v0, p1, Lretrofit2/RequestFactory$Builder;->q:Z

    .line 39
    .line 40
    iput-boolean v0, p0, Lretrofit2/RequestFactory;->i:Z

    .line 41
    .line 42
    iget-boolean v0, p1, Lretrofit2/RequestFactory$Builder;->r:Z

    .line 43
    .line 44
    iput-boolean v0, p0, Lretrofit2/RequestFactory;->j:Z

    .line 45
    .line 46
    iget-object v0, p1, Lretrofit2/RequestFactory$Builder;->w:[Lretrofit2/ParameterHandler;

    .line 47
    .line 48
    iput-object v0, p0, Lretrofit2/RequestFactory;->k:[Lretrofit2/ParameterHandler;

    .line 49
    .line 50
    iget-boolean p1, p1, Lretrofit2/RequestFactory$Builder;->x:Z

    .line 51
    .line 52
    iput-boolean p1, p0, Lretrofit2/RequestFactory;->l:Z

    .line 53
    .line 54
    return-void
.end method
